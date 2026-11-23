#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""poolopt.py — 07xh/proxypool 的隐蔽性工程层（零第三方依赖）

四个组件，对应「像不像正常用户 / 像不像真实客户端 / 像不像人 / 坏代理会不会毁池」：

  AnonymityGate   五判据体检：透明性 / 注入 / 篡改 / 一致性 / 端口面
  Rhythm          每（目标 × 出口）令牌桶 + 对数正态抖动
  FingerprintBook 指纹桶：头顺序模板 + TLS 版本/密码套件/ALPN
  AffinityBook    目标域亲和 + 出口冷却，防「同一 IP 高频 / 同账号跳线」

设计约束：poolsd.py 通过 `from poolopt import ...` 引入，本模块不 import poolsd，
因此可单独测试。代理对象按鸭子类型取 .scheme/.host/.port/.user/.password。
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import random
import ssl
import time

PROBE_404_PATH = "/__pp-must-404-{token}"
PROBE_DEAD_HOST = "pp-dead-{token}.invalid"
FORWARD_HEADERS = ("via", "x-forwarded-for", "forwarded", "proxy-connection",
                   "x-real-ip", "x-forwarded-host", "x-proxy-id", "x-cache-proxy")
HOP_HEADERS = ("via", "x-forwarded-for", "forwarded", "x-real-ip", "x-proxy-id")

# 评分权重：合计 100；注入或篡改任意一项成立 → 直接黑名单
W_TRANSPARENT = 30
W_INJECTION = 25
W_TAMPER = 15
W_STABILITY = 15
W_PORT_SCOPE = 15

GRADE_USABLE = "usable"
GRADE_DEGRADED = "degraded"
GRADE_BLACKLIST = "blacklist"
GRADE_UNUSABLE = "unusable"

# 比对类探针必须两侧发同一组头，否则「差异」是请求不同造成的，不是代理动了手。
# 形变 UAs 只用于透明性探针（那一项的判据就是 UA 是否被改写）。
PROBE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def probe_headers() -> list[tuple[str, str]]:
    return [("User-Agent", PROBE_UA), ("Accept", "*/*"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "identity")]


class TransportError(Exception):
    """建连 / 握手 / 报文解析层失败。"""


# ───────────────────────── 传输（独立实现，便于离线测试） ─────────────────────────

async def _read_head(reader: asyncio.StreamReader, limit: int = 65536):
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
        raise TransportError(f"head incomplete: {type(exc).__name__}") from exc
    if len(data) > limit:
        raise TransportError("head too large")
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = 0
    if lines and lines[0].startswith(b"HTTP/"):
        parts = lines[0].split(b" ")
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                status = 0
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        headers.append((key.decode("latin-1").strip().lower(),
                        value.decode("latin-1").strip()))
    return status, headers, rest


def hget(headers: list[tuple[str, str]], name: str, default: str = "") -> str:
    low = name.lower()
    for key, value in headers:
        if key.lower() == low:
            return value
    return default


def dechunk(payload: bytes) -> bytes:
    out = b""
    while payload:
        head, sep, rest = payload.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(head.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        payload = rest[size + 2:]
    return out


async def _read_body(reader: asyncio.StreamReader, headers: list[tuple[str, str]],
                     limit: int) -> bytes:
    """读响应体：chunked / content-length / EOF 三种定界。"""
    te = hget(headers, "transfer-encoding").lower()
    if "chunked" in te:
        buf = b""
        while len(buf) < limit:
            try:
                chunk = await reader.read(8192)
            except (ConnectionError, asyncio.IncompleteReadError):
                break
            if not chunk:
                break
            buf += chunk
        return dechunk(buf)[:limit]
    raw_len = hget(headers, "content-length", "0") or "0"
    try:
        want = int(raw_len)
    except ValueError:
        want = 0
    if want <= 0:
        try:
            return (await reader.read(limit))[:limit]
        except (ConnectionError, asyncio.IncompleteReadError):
            return b""
    out = b""
    while len(out) < min(want, limit):
        try:
            chunk = await reader.read(min(8192, min(want, limit) - len(out)))
        except (ConnectionError, asyncio.IncompleteReadError):
            break
        if not chunk:
            break
        out += chunk
    return out


async def _read_response(reader: asyncio.StreamReader, max_body: int):
    status, headers, rest = await _read_head(reader)
    te = hget(headers, "transfer-encoding").lower()
    clen = hget(headers, "content-length", "")
    body = b""
    if rest:
        if "chunked" in te:
            body = dechunk(rest)
        elif clen.isdigit():
            body = rest[:int(clen)]
        elif status not in (204, 304) and status >= 200:
            body = rest
    if status in (204, 304) or status < 200:
        return status, headers, b""
    if "chunked" in te and len(body) < max_body:
        tail = await _read_body(reader, headers, max_body - len(body))
        if not rest:
            body = tail
        else:
            body = (body + tail)[:max_body]
        return status, headers, body
    if clen.isdigit() and len(body) < min(int(clen), max_body):
        body += await _read_body(reader, headers, min(int(clen), max_body) - len(body))
    return status, headers, body


async def direct_get(url: str, *, timeout: float = 8.0, headers=None,
                     max_body: int = 2_000_000, profile=None) -> dict:
    """直连取一个 URL，作为内容基线；不经过任何代理。"""
    import urllib.parse
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        raise TransportError(f"bad url: {url}")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    hdrs = list(headers or [])
    if not any(k.lower() == "user-agent" for k, _ in hdrs):
        hdrs.append(("User-Agent", shape_ua(profile)))
    if not any(k.lower() == "accept-encoding" for k, _ in hdrs):
        hdrs.append(("Accept-Encoding", "identity"))
    hdrs.append(("Connection", "close"))
    started = time.monotonic()
    reader = writer = None
    try:
        ctx = None
        if parts.scheme == "https":
            ctx = tls_context(profile)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=host if ctx else None), timeout)
        lines = [f"GET {path} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in hdrs]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await writer.drain()
        status, rheaders, body = await asyncio.wait_for(
            _read_response(reader, max_body), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    return {
        "status": status,
        "headers": rheaders,
        "body": body,
        "body_len": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "elapsed": round(time.monotonic() - started, 4),
        "direct": True,
    }


async def proxy_fetch(proxy, url: str, *, method: str = "GET", headers=None,
                      body: bytes = b"", timeout: float = 8.0,
                      max_body: int = 2_000_000, profile=None) -> dict:
    """经 proxy 取一个 URL：http 目标走 absolute-form，https 目标走 CONNECT+TLS。"""
    import urllib.parse
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        raise TransportError(f"bad url: {url}")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    scheme = getattr(proxy, "scheme", "http").lower()
    user = getattr(proxy, "user", "") or ""
    password = getattr(proxy, "password", "") or ""
    hdrs = list(headers or [])
    started = time.monotonic()
    reader = writer = None

    async def _connect_proxy():
        ctx = tls_context(profile) if scheme == "https" else None
        return await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port, ssl=ctx,
                                    server_hostname=proxy.host if ctx else None),
            timeout)

    try:
        reader, writer = await _connect_proxy()
        if parts.scheme == "https" or scheme in ("socks5", "socks4"):
            if scheme in ("socks5", "socks4"):
                await asyncio.wait_for(
                    _socks5_connect(reader, writer, host, port, user, password), timeout)
            else:
                lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
                if user:
                    lines.append(f"Proxy-Authorization: {basic_auth(user, password)}")
                writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
                await writer.drain()
                status, _, _ = await asyncio.wait_for(_read_head(reader), timeout)
                if status != 200:
                    raise TransportError(f"CONNECT rejected: {status}")
            if parts.scheme == "https":
                ctx = tls_context(profile)
                await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)
            target_line = f"{method} {path} HTTP/1.1"
        else:
            target_line = f"{method} {url} HTTP/1.1"

        lines = [target_line, f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in hdrs]
        if body:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        await writer.drain()
        if scheme in ("socks5", "socks4") and user:
            pass  # SOCKS5 认证在握手阶段完成
        status, rheaders, payload = await asyncio.wait_for(
            _read_response(reader, max_body), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    return {
        "status": status,
        "headers": rheaders,
        "body": payload,
        "body_len": len(payload),
        "body_sha256": hashlib.sha256(payload).hexdigest(),
        "elapsed": round(time.monotonic() - started, 4),
        "direct": False,
    }


def basic_auth(user: str, password: str) -> str:
    import base64
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")


async def _socks5_connect(reader, writer, host, port, user, password) -> None:
    import socket as _socket
    methods = b"\x05\x02\x00\x02" if user else b"\x05\x01\x00"
    writer.write(methods)
    await writer.drain()
    head = await reader.readexactly(2)
    if head[0] != 0x05:
        raise TransportError("socks5: bad version")
    if head[1] == 0x02:
        if not user:
            raise TransportError("socks5: auth required")
        ub, pb = user.encode(), password.encode()
        writer.write(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        await writer.drain()
        auth = await reader.readexactly(2)
        if auth[1] != 0x00:
            raise TransportError("socks5: auth failed")
    elif head[1] != 0x00:
        raise TransportError("socks5: no acceptable method")
    try:
        _socket.inet_aton(host)
        addr = b"\x01" + _socket.inet_aton(host)
    except OSError:
        encoded = host.encode()
        if len(encoded) > 255:
            raise TransportError("socks5: host too long")
        addr = b"\x03" + bytes([len(encoded)]) + encoded
    writer.write(b"\x05\x01\x00" + addr + int(port).to_bytes(2, "big"))
    await writer.drain()
    rep = await reader.readexactly(4)
    if rep[1] != 0x00:
        raise TransportError(f"socks5: connect failed code={rep[1]}")
    if rep[3] == 0x01:
        await reader.readexactly(6)
    elif rep[3] == 0x03:
        length = await reader.readexactly(1)
        await reader.readexactly(length[0] + 2)
    elif rep[3] == 0x04:
        await reader.readexactly(18)


async def connect_probe(proxy, host: str, port: int, timeout: float = 4.0) -> bool:
    """只测 CONNECT 是否放行该端口，不发送任何业务数据。"""
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout)
        writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
                     .encode("latin-1"))
        await writer.drain()
        status, _, _ = await asyncio.wait_for(_read_head(reader), timeout)
        return status == 200
    except (OSError, asyncio.TimeoutError, ssl.SSLError, TransportError):
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


# ───────────────────────── 指纹桶 ─────────────────────────

class Profile:
    """一个可复用的客户端画像：头顺序模板 + TLS 参数。"""

    __slots__ = ("name", "ua", "order", "lang", "ciphers", "alpn", "min_tls", "extra")

    def __init__(self, name: str, ua: str, order: tuple, lang: str,
                 ciphers: str = "", alpn: tuple = (), min_tls=None,
                 extra: dict | None = None) -> None:
        self.name = name
        self.ua = ua
        self.order = order
        self.lang = lang
        self.ciphers = ciphers
        self.alpn = alpn
        self.min_tls = min_tls
        self.extra = extra or {}


CHROME_H2 = (
    "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "upgrade-insecure-requests", "user-agent", "accept",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
    "referer", "accept-encoding", "accept-language", "cookie",
)
FIREFOX_H2 = (
    "host", "connection", "user-agent", "accept",
    "accept-language", "accept-encoding", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "referer", "cookie",
)
SAFARI_H2 = (
    "host", "connection", "user-agent", "accept", "accept-language",
    "accept-encoding", "referer", "cookie",
)

CHROME_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA:DES-CBC3-SHA"
)
FIREFOX_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
)
SAFARI_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:"
    "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA"
)


def default_profiles() -> list[Profile]:
    """5–8 桶是经验区间：太少会被聚类，太多每桶样本过少反而异常。"""
    return [
        Profile("chrome131-win", (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            CHROME_H2, "zh-CN,zh;q=0.9,en;q=0.8", CHROME_CIPHERS, ("h2", "http/1.1"),
            extra={"sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                   "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"'}),
        Profile("chrome124-mac", (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            CHROME_H2, "en-US,en;q=0.9", CHROME_CIPHERS, ("h2", "http/1.1"),
            extra={"sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                   "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"macOS"'}),
        Profile("firefox128-win", (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
            "Gecko/20100101 Firefox/128.0"),
            FIREFOX_H2, "zh-CN,zh;q=0.8,zh-TW;q=0.7,en-US;q=0.5,en;q=0.3",
            FIREFOX_CIPHERS, ("http/1.1",), extra={}),
        Profile("firefox115-linux", (
            "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"),
            FIREFOX_H2, "en-US,en;q=0.5", FIREFOX_CIPHERS, ("http/1.1",), extra={}),
        Profile("safari17-mac", (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15"),
            SAFARI_H2, "zh-CN,zh-Hans;q=0.9", SAFARI_CIPHERS, ("h2", "http/1.1"),
            extra={}),
        Profile("edge131-win", (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
            CHROME_H2, "zh-CN,zh;q=0.9,en;q=0.8", CHROME_CIPHERS, ("h2", "http/1.1"),
            extra={"sec-ch-ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
                   "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"'}),
    ]


def tls_context(profile: Profile | None) -> ssl.SSLContext:
    """按画像生成 TLS 上下文：密码顺序、ALPN、最低版本都会影响 JA3/JA4。"""
    ctx = ssl.create_default_context()
    if profile is None:
        return ctx
    if profile.ciphers:
        try:
            ctx.set_ciphers(profile.ciphers)
        except ssl.SSLError:
            pass
    if profile.alpn:
        try:
            ctx.set_alpn_protocols(list(profile.alpn))
        except NotImplementedError:
            pass
    return ctx


def shape_ua(profile: Profile | None) -> str:
    if profile is None:
        return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    return profile.ua


def shape_request(profile: Profile, headers: list[tuple[str, str]],
                  host_header: str) -> list[tuple[str, str]]:
    """按画像顺序重排请求头，并在缺项时补该画像的默认头。

    未知头保持原相对顺序追加在模板之后——不丢头、不重排未知头，
    避免出现「顺序正确但少了 Cookie」这种更明显的异常。
    """
    present: dict[str, list[str]] = {}
    originals: list[tuple[str, str, str]] = []
    for key, value in headers:
        low = key.lower()
        if low in ("host", "connection", "proxy-connection", "proxy-authorization",
                   "keep-alive", "te", "trailer", "upgrade"):
            continue
        present.setdefault(low, []).append(value)
        originals.append((low, key, value))

    defaults = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": profile.lang,
        "connection": "close",
        "user-agent": profile.ua,
        "upgrade-insecure-requests": "1",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    defaults.update(profile.extra)
    # 这三项必须跟画像一致：UA 与 TLS 指纹错配（curl UA + Chrome 密码套件）
    # 比「头序稍微不自然」明显得多，所以强制覆盖，不保留客户端原值。
    forced = {"user-agent": profile.ua, "accept-language": profile.lang,
              "accept-encoding": defaults["accept-encoding"]}
    ordered: list[tuple[str, str]] = [("Host", host_header)]
    used: set[str] = set()
    for name in profile.order:
        if name in ("host", "connection"):
            continue
        if name in forced:
            ordered.append((canonical(name), forced[name]))
            used.add(name)
            continue
        if name in present:
            for value in present[name]:
                ordered.append((canonical(name), value))
            used.add(name)
        elif name in defaults:
            ordered.append((canonical(name), defaults[name]))
    for low, key, value in originals:
        if low in used or low in profile.order:
            continue
        ordered.append((key, value))
        used.add(low)
    ordered.append(("Connection", "close"))
    return ordered


_HEADER_CASE = {
    "user-agent": "User-Agent", "accept": "Accept", "accept-language": "Accept-Language",
    "accept-encoding": "Accept-Encoding", "referer": "Referer", "cookie": "Cookie",
    "origin": "Origin", "content-type": "Content-Type", "content-length": "Content-Length",
    "connection": "Connection", "host": "Host", "authorization": "Authorization",
    "upgrade-insecure-requests": "Upgrade-Insecure-Requests", "if-none-match": "If-None-Match",
    "if-modified-since": "If-Modified-Since", "cache-control": "Cache-Control",
    "pragma": "Pragma", "range": "Range", "x-requested-with": "X-Requested-With",
}


def canonical(name: str) -> str:
    return _HEADER_CASE.get(name.lower(), "-".join(p.capitalize() for p in name.split("-")))


class FingerprintBook:
    """把出口绑到固定的画像桶；同一出口永远同一画像，跨请求不漂移。"""

    def __init__(self, profiles: list[Profile] | None = None) -> None:
        self.profiles = profiles or default_profiles()

    def assign(self, key: str) -> Profile:
        digest = int(hashlib.blake2b(key.encode(), digest_size=4).hexdigest(), 16)
        return self.profiles[digest % len(self.profiles)]

    def by_name(self, name: str) -> Profile | None:
        for profile in self.profiles:
            if profile.name == name:
                return profile
        return None


# ───────────────────────── 节律 ─────────────────────────

def human_delay(mu: float = 2.2, sigma: float = 0.6) -> float:
    """对数正态间隔；固定 sleep 的方差≈0，是最容易被分类器抓住的特征。

    mu<=0 或 sigma<=0 时退化为无抖动（0.0），供「严格按令牌桶」的场合使用；
    对数正态要求 mu>0，直接 log(0) 会抛 ValueError。
    """
    if mu <= 0.0 or sigma <= 0.0:
        return 0.0
    return max(0.15, random.lognormvariate(math.log(mu), sigma))


class TokenBucket:
    def __init__(self, capacity: int = 5, refill_per_sec: float = 0.5) -> None:
        self.capacity = float(capacity)
        self.rate = float(refill_per_sec)
        self.tokens = float(capacity)
        self.ts = time.monotonic()

    def take(self) -> float:
        """返回需要等待的秒数；0 表示立刻可用。"""
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return 0.0
        need = (1.0 - self.tokens) / self.rate if self.rate > 0 else 0.0
        self.tokens = 0.0
        return need


class Rhythm:
    """每（目标 × 出口）独立配额 + 全局配额 + 抖动。"""

    def __init__(self, mu: float = 1.6, sigma: float = 0.6,
                 per_key_qps: float = 0.5, global_qps: float = 2.0,
                 jitter: bool = True) -> None:
        self.mu = mu
        self.sigma = sigma
        self.per_key_qps = per_key_qps
        self.global_qps = global_qps
        self.jitter = jitter
        self._buckets: dict[str, TokenBucket] = {}
        self._global = TokenBucket(capacity=10, refill_per_sec=global_qps)

    def _bucket(self, key: str) -> TokenBucket:
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(capacity=5, refill_per_sec=self.per_key_qps)
        return self._buckets[key]

    def delay_for(self, host: str, proxy_key: str) -> float:
        wait = self._global.take()
        wait = max(wait, self._bucket(f"{host}|{proxy_key}").take())
        if self.jitter:
            wait += human_delay(self.mu, self.sigma)
        return wait

    async def wait(self, host: str, proxy_key: str) -> float:
        delay = self.delay_for(host, proxy_key)
        if delay > 0:
            await asyncio.sleep(delay)
        return delay


# ───────────────────────── 亲和与冷却 ─────────────────────────

class AffinityBook:
    """目标域亲和 + 出口冷却。

    亲和：同一目标域在窗口内尽量复用同一出口（登录态、下单流程不跳 IP）。
    冷却：同一出口在冷却窗口内不再承接同一目标域（防单 IP 高频）。
    """

    def __init__(self, affinity_ttl: float = 900.0, cooldown: float = 60.0,
                 max_per_host: int = 1) -> None:
        self.affinity_ttl = affinity_ttl
        self.cooldown = cooldown
        self.max_per_host = max_per_host
        self._affinity: dict[str, tuple[str, float]] = {}
        self._last_use: dict[tuple[str, str], float] = {}
        self._host_counts: dict[str, dict[str, int]] = {}

    def affinity(self, host: str) -> str | None:
        hit = self._affinity.get(host)
        if not hit or hit[1] <= time.time():
            return None
        return hit[0]

    def bind(self, host: str, key: str) -> None:
        self._affinity[host] = (key, time.time() + self.affinity_ttl)

    def touch(self, host: str, key: str) -> None:
        self._last_use[(host, key)] = time.time()
        counts = self._host_counts.setdefault(host, {})
        counts[key] = counts.get(key, 0) + 1

    def cooling(self, host: str, key: str) -> bool:
        last = self._last_use.get((host, key))
        return bool(last) and (time.time() - last) < self.cooldown

    def purge(self) -> None:
        now = time.time()
        self._affinity = {h: v for h, v in self._affinity.items() if v[1] > now}
        horizon = now - max(self.cooldown, 300.0)
        self._last_use = {k: v for k, v in self._last_use.items() if v > horizon}
        for host in list(self._host_counts):
            if not any((host, key) in self._last_use for key in self._host_counts[host]):
                self._host_counts.pop(host, None)

    def stats(self) -> dict:
        return {"affinity": len(self._affinity),
                "recent_pairs": len(self._last_use),
                "hosts": len(self._host_counts)}


# ───────────────────────── 五判据体检 ─────────────────────────

class AnonymityGate:
    """五判据：透明性 / 注入 / 篡改 / 一致性 / 端口面。

    baseline 走直连；同一目标 5 分钟内复用基线，避免每次体检重复打目标。
    """

    def __init__(self, targets: list[str], *, timeout: float = 8.0,
                 max_body: int = 262144, baseline_ttl: float = 300.0,
                 port_scope_host: str = "example.com",
                 port_scope_ports: tuple = (22, 25, 6379),
                 fingerprint: FingerprintBook | None = None) -> None:
        self.targets = list(targets)
        self.timeout = timeout
        self.max_body = max_body
        self.baseline_ttl = baseline_ttl
        self.port_scope_host = port_scope_host
        self.port_scope_ports = port_scope_ports
        self.fingerprint = fingerprint or FingerprintBook()
        self._baseline: dict[str, tuple[float, dict]] = {}
        self._rr = 0
        self.port_scope_reachable = True

    def _target(self) -> str:
        if not self.targets:
            return "http://httpbin.org/ip"
        target = self.targets[self._rr % len(self.targets)]
        self._rr += 1
        return target

    async def baseline(self, url: str) -> dict:
        hit = self._baseline.get(url)
        if hit and hit[0] > time.time():
            return hit[1]
        try:
            result = await direct_get(url, timeout=self.timeout, max_body=self.max_body,
                                      headers=probe_headers())
        except TransportError as exc:
            result = {"status": 0, "body": b"", "body_len": 0,
                      "body_sha256": "", "error": str(exc)}
        self._baseline[url] = (time.time() + self.baseline_ttl, result)
        return result

    async def _transparency(self, proxy) -> dict:
        marker = "PPUA" + hashlib.blake2b(
            f"{proxy.host}:{proxy.port}".encode(), digest_size=5).hexdigest().upper()
        out = {"marker": marker, "leaked_headers": [], "ua_rewritten": None,
               "echoed": False}
        try:
            result = await proxy_fetch(proxy, self._target(), timeout=self.timeout,
                                       headers=[("User-Agent", marker)],
                                       max_body=self.max_body)
        except TransportError as exc:
            out["error"] = str(exc)
            return out
        out["status"] = result["status"]
        out["leaked_headers"] = [k for k in FORWARD_HEADERS
                                 if hget(result["headers"], k)]
        body = result["body"]
        text = body.decode("utf-8", "replace")
        if marker in text:
            out["echoed"] = True
            out["ua_rewritten"] = False
        elif '"user-agent"' in text.lower() or "user-agent:" in text.lower():
            out["echoed"] = True
            out["ua_rewritten"] = True
        out["ok"] = (200 <= result["status"] < 400
                     and not out["leaked_headers"]
                     and out["ua_rewritten"] is not True)
        return out

    async def _injection(self, proxy) -> dict:
        import urllib.parse
        target = self._target()
        parts = urllib.parse.urlsplit(target)
        root = f"{parts.scheme}://{parts.netloc}"
        token = hashlib.blake2b(f"{proxy.host}:{proxy.port}".encode(),
                                digest_size=6).hexdigest()
        out = {"fake_404": False, "fake_dead_host": False, "injected": False}
        try:
            probe = await proxy_fetch(
                proxy, root + PROBE_404_PATH.format(token=token),
                timeout=self.timeout, max_body=self.max_body)
            out["status_404"] = probe["status"]
            if probe["status"] in (200, 203):
                out["fake_404"] = True
                out["body_404_sha256"] = probe["body_sha256"][:16]
        except TransportError as exc:
            out["error_404"] = str(exc)
        try:
            dead = await proxy_fetch(
                proxy, "http://" + PROBE_DEAD_HOST.format(token=token) + "/",
                timeout=self.timeout, max_body=self.max_body)
            out["status_dead"] = dead["status"]
            if dead["status"] in (200, 203):
                out["fake_dead_host"] = True
                out["body_dead_sha256"] = dead["body_sha256"][:16]
        except TransportError as exc:
            out["error_dead"] = str(exc)
        out["injected"] = out["fake_404"] or out["fake_dead_host"]
        return out

    async def _tamper(self, proxy) -> dict:
        url = self._target()
        base = await self.baseline(url)
        out = {"tampered": False, "delta_len": 0, "sha_equal": False}
        try:
            probe = await proxy_fetch(proxy, url, timeout=self.timeout,
                                      max_body=self.max_body,
                                      headers=probe_headers())
        except TransportError as exc:
            out["error"] = str(exc)
            return out
        out["status"] = probe["status"]
        out["sha_equal"] = probe["body_sha256"] == base.get("body_sha256", "")
        out["delta_len"] = probe["body_len"] - int(base.get("body_len", 0))
        base_len = max(int(base.get("body_len", 0)), 1)
        ratio = abs(out["delta_len"]) / base_len
        out["tampered"] = (not out["sha_equal"]) and ratio > 0.02
        if not out["sha_equal"] and not out["tampered"]:
            out["note"] = "body differs <2%（动态内容，可能是时间戳/随机 token）"
        return out

    async def _stability(self, proxy) -> dict:
        url = self._target()
        out = {"lens": [], "cv": None, "stable": False}
        for i in range(2):
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}_pp={int(time.time() * 1000)}_{i}"
            try:
                result = await proxy_fetch(proxy, probe_url, timeout=self.timeout,
                                           max_body=self.max_body,
                                           headers=probe_headers())
                out["lens"].append(result["body_len"])
            except TransportError:
                out["lens"].append(-1)
        valid = [n for n in out["lens"] if n >= 0]
        if len(valid) >= 2:
            mean = sum(valid) / len(valid)
            if mean > 0:
                var = sum((n - mean) ** 2 for n in valid) / len(valid)
                out["cv"] = round(math.sqrt(var) / mean, 4)
                out["stable"] = out["cv"] < 0.02
        return out

    async def _port_scope(self, proxy) -> dict:
        opened = []
        for port in self.port_scope_ports:
            if await connect_probe(proxy, self.port_scope_host, port, timeout=4.0):
                opened.append(port)
        return {"open_ports": opened,
                "http_only": not opened,
                "assessable": bool(self.port_scope_ports),
                "risk": "high" if len(opened) >= 2 else ("medium" if opened else "low")}

    def score(self, record: dict) -> dict:
        total = 0.0
        if record["transparency"].get("ok"):
            total += W_TRANSPARENT
        if not record["injection"].get("injected"):
            total += W_INJECTION
        if not record["tamper"].get("tampered"):
            total += W_TAMPER
        if record["stability"].get("stable"):
            total += W_STABILITY
        if record["port_scope"].get("http_only"):
            total += W_PORT_SCOPE
        record["score"] = round(total, 2)
        if record["injection"].get("injected") or record["tamper"].get("tampered"):
            record["grade"] = GRADE_BLACKLIST
        elif total >= 85:
            record["grade"] = GRADE_USABLE
        elif total >= 60:
            record["grade"] = GRADE_DEGRADED
        else:
            record["grade"] = GRADE_UNUSABLE
        return record

    async def audit(self, proxy, *, deep: bool = True) -> dict:
        record = {
            "key": f"{getattr(proxy, 'scheme', 'http')}://{proxy.host}:{proxy.port}",
            "transparency": await self._transparency(proxy),
            "injection": await self._injection(proxy),
            "tamper": await self._tamper(proxy),
            "stability": await self._stability(proxy) if deep else {"stable": True},
            "port_scope": await self._port_scope(proxy) if deep else {"http_only": True},
            "ts": time.time(),
        }
        return self.score(record)

    async def content_ok(self, proxy, url: str) -> tuple[bool, str]:
        """L2：与直连基线比内容。体检链路里最便宜的一道真判据。"""
        base = await self.baseline(url)
        if not base.get("body_sha256"):
            return True, "baseline-unavailable"
        try:
            probe = await proxy_fetch(proxy, url, timeout=self.timeout,
                                      max_body=self.max_body,
                                      headers=probe_headers())
        except TransportError as exc:
            return False, f"fetch:{type(exc).__name__}"
        if probe["body_sha256"] == base["body_sha256"]:
            return True, "sha-match"
        base_len = max(int(base.get("body_len", 0)), 1)
        ratio = abs(probe["body_len"] - base_len) / base_len
        if ratio > 0.02:
            return False, f"len-delta:{int(ratio * 100)}%"
        return True, "dynamic-content"

    async def stability_ok(self, proxy) -> tuple[bool, str]:
        result = await self._stability(proxy)
        if result.get("cv") is None:
            return True, "no-sample"
        return bool(result["stable"]), f"cv={result['cv']}"