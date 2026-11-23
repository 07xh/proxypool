#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poolsd.py — 通用代理池守护进程（零第三方依赖，纯标准库）

一个进程同时提供三样东西：
  1) HTTP API        —— 宿主程序按需取代理（JSON / 文本 / curl 参数 / 环境变量）
  2) 本地代理网关     —— 把整个池子伪装成 127.0.0.1 上的一个固定 HTTP 代理，
                        任何支持代理的程序（curl/requests/scrapy/Chrome/Selenium）
                        只要配一个地址就自动轮换、自动重试换线
  3) 健康检查器       —— 并发探测、延迟平滑、失败退避、死代理自动复活

用法:
  python poolsd.py -c pool.json
  python poolsd.py --selftest          # 内置自测：本地假代理 + 假目标，全链路断言
  python poolsd.py --once              # 只体检一轮后退出（给 cron / CI 用）

对外契约见 README.md 与 poolclient.py。
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import ipaddress
import json
import os
import random
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
from types import SimpleNamespace
from typing import Any, Optional

from public_sources import PublicSourceManager
from direct_nodes import DirectNodeStore

import poolopt
from poolopt import (AffinityBook, AnonymityGate, FingerprintBook, Rhythm,
                     TransportError, canonical, human_delay, shape_request,
                     shape_ua, tls_context)

VERSION = "1.0.0"
CHUNK = 65536
MAX_HEAD = 256 * 1024
MAX_BODY = 8 * 1024 * 1024  # gateway request bodies; management API stays smaller
MAX_RESPONSE_BYTES = 64 * 1024 * 1024  # reject, never return a partial upstream response
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# ───────────────────────────── 配置 ─────────────────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "api": {
        "host": "127.0.0.1",
        "port": 18081,
        "token": "",            # 非空则要求 Authorization: Bearer <token>
    },
    "gateway": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 18080,
        "auth": "",             # "user:pass" 非空则要求 Proxy-Authorization
        "max_retry": 2,         # 一个客户端请求最多换 max_retry+1 个上游
        "retry_on_status": [502, 503, 504],
        "direct_fallback": False,  # 池空 / 全死时是否直连兜底
        "connect_timeout": 15.0,
        "idle_timeout": 120.0,
        "rhythm_enabled": True,   # 每（目标×出口）令牌桶 + 对数正态抖动
        "shape_headers": True,    # 按出口画像重排头序、补默认头
    },
    "hardening": {
        "affinity_ttl": 900,      # 目标域亲和窗口（秒）：同域复用同一出口
        "proxy_cooldown": 60,     # 同一出口对同一目标域的冷却（秒）
        "rhythm_mu": 1.6,         # 对数正态均值（秒）
        "rhythm_sigma": 0.6,      # 对数正态 sigma；0 = 固定节律（不推荐）
        "per_key_qps": 0.5,       # 每（目标×出口）补充速率
        "global_qps": 2.0,        # 全局补充速率
        "port_scope_host": "example.com",
        "port_scope_ports": [22, 25, 6379],
    },
    "checker": {
        "enabled": True,
        "interval": 120,        # 秒；0 表示不周期体检
        "concurrency": 64,
        "timeout": 8.0,
        "targets": [
            "http://www.gstatic.com/generate_204",
            "http://httpbin.org/ip",
        ],
        "expect_contains": "",  # 非空则要求响应体包含该串（防拦截页冒充健康）
        "content_check": False,  # L2：与直连基线比 sha256；目标回显请求头/动态内容时须关闭
        "startup_sweep": True,
        "max_bytes": 32768,
    },
    "pool": {
        "strategy": "weighted_random",   # weighted_random | round_robin | fastest | random
        "sticky_ttl": 300,               # 粘性会话秒数
        "allow_cold_start": True,        # 还没体检完时允许临时使用 new 代理
        "max_dead_retry": 3,             # 连续失败多少次判死
    },
    "storage": {
        "db": "proxies.db",
        "flush_interval": 5,
        "persist_credentials": False,
    },
    "public_sources": [],  # optional public HTTPS feeds; disabled unless configured
    "direct_nodes": {"path": "direct_nodes.local.txt", "allowed_hosts": ["kyfw.12306.cn"], "max_age_hours": 72},
    "sources": [],   # [{"type":"file","path":"proxies.txt","interval":0},
                     #  {"type":"url","url":"http://...","interval":600}]
    "log_level": "info",
}


def deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def ns(d: Any) -> Any:
    if isinstance(d, dict):
        return SimpleNamespace(**{k: ns(v) for k, v in d.items()})
    if isinstance(d, list):
        return [ns(x) for x in d]
    return d


def load_config(path: Optional[str]) -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg = deep_merge(cfg, json.load(f))
    # 环境变量覆盖，方便容器化宿主
    if os.environ.get("PROXYPOOL_API_PORT"):
        cfg["api"]["port"] = int(os.environ["PROXYPOOL_API_PORT"])
    if os.environ.get("PROXYPOOL_GATEWAY_PORT"):
        cfg["gateway"]["port"] = int(os.environ["PROXYPOOL_GATEWAY_PORT"])
    if os.environ.get("PROXYPOOL_API_TOKEN"):
        cfg["api"]["token"] = os.environ["PROXYPOOL_API_TOKEN"]
    if os.environ.get("PROXYPOOL_DB"):
        cfg["storage"]["db"] = os.environ["PROXYPOOL_DB"]
    return cfg


def resolve_runtime_paths(cfg: dict, base_dir: str | os.PathLike) -> dict:
    """Return an isolated configuration with local file paths anchored to base_dir.

    Desktop backends must not call os.chdir(): the working directory is
    process-global and changing it on a background thread affects the GUI.
    URL sources and absolute paths remain unchanged.
    """
    out = copy.deepcopy(cfg)
    base = os.path.abspath(os.fspath(base_dir))

    def anchored(value):
        if not isinstance(value, str) or not value:
            return value
        return value if os.path.isabs(value) else os.path.abspath(os.path.join(base, value))

    for group, field in (("storage", "db"), ("direct_nodes", "path")):
        section = out.get(group)
        if isinstance(section, dict) and field in section:
            section[field] = anchored(section[field])

    for source in out.get("sources", []):
        if isinstance(source, dict) and source.get("type", "file") == "file":
            if "path" in source:
                source["path"] = anchored(source["path"])
    return out


# ───────────────────────────── 工具 ─────────────────────────────

LOG_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}
_log_level = 20


def log(level: str, msg: str, *args: Any) -> None:
    if LOG_LEVELS.get(level, 20) < _log_level:
        return
    if args:
        try:
            msg = msg % args
        except Exception:
            pass
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level.upper()}] {msg}", flush=True)


def basic_header(user: str, password: str) -> str:
    raw = f"{user}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def parse_basic(value: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(value.split(None, 1)[-1]).decode("utf-8", "replace")
        u, _, p = raw.partition(":")
        return u, p
    except Exception:
        return "", ""


def verified_tls_context() -> ssl.SSLContext:
    """Validate the certificate and hostname of HTTPS peers."""
    return ssl.create_default_context()


def proxy_key(scheme: str, host: str, port: int) -> str:
    return f"{scheme.lower()}://{host.lower()}:{int(port)}"


def split_proxy_text(line: str) -> Optional[dict]:
    """解析一行代理文本，支持:
       1.2.3.4:8080
       http://1.2.3.4:8080
       http://user:pass@1.2.3.4:8080
       socks5://user:pass@1.2.3.4:1080
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = "http://" + s
    try:
        u = urllib.parse.urlsplit(s)
    except Exception:
        return None
    if not u.hostname:
        return None
    scheme = (u.scheme or "http").lower()
    if scheme not in ("http", "https", "socks5", "socks4"):
        scheme = "http"
    try:
        port = u.port or (1080 if scheme.startswith("socks") else 8080)
    except ValueError:
        return None
    return {
        "scheme": scheme,
        "host": u.hostname,
        "port": int(port),
        "user": urllib.parse.unquote(u.username or ""),
        "password": urllib.parse.unquote(u.password or ""),
    }


def proxy_url(p: "Proxy", with_auth: bool = True) -> str:
    if with_auth and p.user:
        u = urllib.parse.quote(p.user, safe="")
        pw = urllib.parse.quote(p.password, safe="")
        return f"{p.scheme}://{u}:{pw}@{p.host}:{p.port}"
    return f"{p.scheme}://{p.host}:{p.port}"


async def read_head(reader: asyncio.StreamReader) -> tuple[str, list[tuple[str, str]]]:
    data = await reader.readuntil(b"\r\n\r\n")
    head = data.decode("latin-1")
    lines = head.split("\r\n")
    first = lines[0]
    headers: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if not ln:
            continue
        k, _, v = ln.partition(":")
        headers.append((k.strip(), v.strip()))
    return first, headers


def hget(headers: list[tuple[str, str]], name: str) -> str:
    low = name.lower()
    for k, v in headers:
        if k.lower() == low:
            return v
    return ""


class BodyTooLarge(ValueError):
    """The declared or decoded body exceeds the configured byte limit."""


class MalformedBody(ValueError):
    """Invalid or ambiguous HTTP/1.1 message framing."""


async def read_body(reader: asyncio.StreamReader, headers: list[tuple[str, str]],
                    limit: int = MAX_HEAD, strict: bool = True) -> bytes:
    """Decode a bounded body. strict=False is only for read-only health responses.

    The gateway forwards decoded chunks with a recalculated Content-Length.
    Ambiguous Content-Length / Transfer-Encoding combinations are rejected.
    """
    encodings = [v.strip().lower() for k, v in headers
                 if k.lower() == "transfer-encoding"]
    lengths = [v.strip() for k, v in headers if k.lower() == "content-length"]
    if len(lengths) > 1 or len(encodings) > 1 or (encodings and lengths):
        raise MalformedBody("ambiguous request framing")
    if encodings:
        if encodings[0] != "chunked":
            raise MalformedBody("unsupported transfer-encoding")
        out = bytearray()
        while True:
            line = await reader.readuntil(b"\r\n")
            chunk_size = line[:-2].split(b";", 1)[0].strip()
            if not chunk_size or any(c not in b"0123456789abcdefABCDEF" for c in chunk_size):
                raise MalformedBody("bad chunk size")
            n = int(chunk_size, 16)
            if n == 0:
                trailer_size = 0
                while True:
                    trailer = await reader.readuntil(b"\r\n")
                    trailer_size += len(trailer)
                    if trailer_size > 16384:
                        raise MalformedBody("trailers too large")
                    if trailer == b"\r\n":
                        return bytes(out)
            remaining = limit - len(out)
            if n > remaining:
                if strict:
                    raise BodyTooLarge("chunked body too large")
                out.extend(await reader.readexactly(remaining))
                return bytes(out)
            out.extend(await reader.readexactly(n))
            if await reader.readexactly(2) != b"\r\n":
                raise MalformedBody("missing chunk terminator")
    if lengths:
        if not lengths[0].isdigit():
            raise MalformedBody("bad content-length")
        n = int(lengths[0])
        if n > limit:
            if strict:
                raise BodyTooLarge("content-length too large")
            n = limit
        return await reader.readexactly(n)
    return b""

def http_response(status: int, reason: str, headers: list[tuple[str, str]],
                  body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if not any(k.lower() == "content-length" for k, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def json_response(obj: Any, status: int = 200) -> bytes:
    body = json.dumps(obj, ensure_ascii=False, indent=None).encode("utf-8")
    return http_response(status, "OK" if status == 200 else "Error",
                         [("Content-Type", "application/json; charset=utf-8"),
                          ("Connection", "close")], body)


def ensure_complete_upstream_response(raw: bytes, request_method: str = "GET") -> None:
    """Reject truncated HTTP/1.1 responses before they reach callers.

    For close-delimited responses, receiving EOF is the completeness signal.
    For framed responses, validate the declared message boundary as well.
    """
    start = 0
    while True:
        end = raw.find(b"\r\n\r\n", start)
        if end < 0 or end - start > MAX_HEAD:
            raise MalformedBody("upstream response has no complete header")
        lines = raw[start:end].split(b"\r\n")
        first = lines[0].split()
        if len(first) < 2 or not first[0].startswith(b"HTTP/"):
            raise MalformedBody("invalid upstream status line")
        try:
            status = int(first[1])
        except ValueError as exc:
            raise MalformedBody("invalid upstream status code") from exc
        if not 100 <= status <= 599:
            raise MalformedBody("upstream status code outside HTTP range")
        headers = []
        for line in lines[1:]:
            if b":" not in line:
                raise MalformedBody("invalid upstream header")
            k, v = line.split(b":", 1)
            headers.append((k.strip().lower(), v.strip()))
        start = end + 4
        if 100 <= status < 200 and status != 101:
            if start >= len(raw):
                raise MalformedBody("informational response lacks final response")
            continue
        body = raw[start:]
        if request_method.upper() == "HEAD" or status in (101, 204, 304):
            if body:
                raise MalformedBody("unexpected body for response without content")
            return

        lengths = [v for k, v in headers if k == b"content-length"]
        encodings = [v.lower() for k, v in headers if k == b"transfer-encoding"]
        if len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings):
            raise MalformedBody("ambiguous upstream message framing")
        if encodings and encodings[0].split(b",")[-1].strip() == b"chunked":
            pos = 0
            trailer_bytes = 0
            while True:
                crlf = body.find(b"\r\n", pos)
                if crlf < 0:
                    raise MalformedBody("truncated upstream chunk size")
                size_text = body[pos:crlf].split(b";", 1)[0].strip()
                if not size_text or any(ch not in b"0123456789abcdefABCDEF"
                                        for ch in size_text):
                    raise MalformedBody("invalid upstream chunk size")
                size = int(size_text, 16)
                pos = crlf + 2
                if size == 0:
                    while True:
                        line_end = body.find(b"\r\n", pos)
                        if line_end < 0:
                            raise MalformedBody("truncated upstream chunk trailers")
                        trailer_bytes += line_end + 2 - pos
                        if trailer_bytes > 16384:
                            raise MalformedBody("upstream chunk trailers too large")
                        trailer = body[pos:line_end]
                        pos = line_end + 2
                        if not trailer:
                            if pos != len(body):
                                raise MalformedBody("unexpected bytes after chunked response")
                            return
                if size > len(body) - pos - 2 or body[pos + size:pos + size + 2] != b"\r\n":
                    raise MalformedBody("truncated or invalid upstream chunk data")
                pos += size + 2
        elif lengths:
            if not lengths[0].isdigit():
                raise MalformedBody("invalid upstream content-length")
            if len(body) != int(lengths[0]):
                raise MalformedBody("upstream content-length does not match received body")
        # Otherwise the response is close-delimited, and EOF completed it.
        return


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await src.read(CHUNK)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        pass
    except Exception:
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


# ───────────────────────────── 代理对象 ─────────────────────────────

class Proxy:
    __slots__ = ("id", "scheme", "host", "port", "user", "password", "region",
                 "source", "enabled", "state", "latency_ms", "ema_ok", "success",
                 "fail", "consec_fail", "last_ok", "last_check", "dead_until",
                 "uses", "score", "grade", "profile", "audit")

    def __init__(self, pid: int, scheme: str, host: str, port: int,
                 user: str = "", password: str = "", region: str = "",
                 source: str = "", enabled: bool = True) -> None:
        self.id = pid
        self.scheme = scheme
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.region = region
        self.source = source
        self.enabled = bool(enabled)
        self.state = "new"
        self.latency_ms = 0.0
        self.ema_ok = 0.5
        self.success = 0
        self.fail = 0
        self.consec_fail = 0
        self.last_ok = 0.0
        self.last_check = 0.0
        self.dead_until = 0.0
        self.uses = 0
        self.score = 0.5
        self.grade = ""          # poolopt 五判据结论；空表示尚未体检
        self.profile = ""        # 指纹桶名，由 FingerprintBook 按 key 固定分配
        self.audit = {}          # 最近一次体检明细{sub-checks}

    @property
    def key(self) -> str:
        return proxy_key(self.scheme, self.host, self.port)

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self, with_auth: bool = False) -> dict:
        return {
            "id": self.id,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "user": self.user if with_auth else "",
            "password": self.password if with_auth else "",
            "region": self.region,
            "source": self.source,
            "enabled": self.enabled,
            "state": self.state,
            "grade": self.grade,
            "profile": self.profile,
            "url": proxy_url(self, with_auth),
            "latency_ms": round(self.latency_ms, 1),
            "score": round(self.score, 4),
            "success": self.success,
            "fail": self.fail,
            "consec_fail": self.consec_fail,
            "uses": self.uses,
            "last_ok": int(self.last_ok),
        }


# ───────────────────────────── 持久化 ─────────────────────────────

class Store:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS proxies (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scheme    TEXT NOT NULL,
        host      TEXT NOT NULL,
        port      INTEGER NOT NULL,
        user      TEXT DEFAULT '',
        password  TEXT DEFAULT '',
        region    TEXT DEFAULT '',
        source    TEXT DEFAULT '',
        enabled   INTEGER DEFAULT 1,
        state     TEXT DEFAULT 'new',
        latency   REAL DEFAULT 0,
        score     REAL DEFAULT 0.5,
        success   INTEGER DEFAULT 0,
        fail      INTEGER DEFAULT 0,
        consec    INTEGER DEFAULT 0,
        last_ok   REAL DEFAULT 0,
        last_chk  REAL DEFAULT 0,
        dead_till REAL DEFAULT 0,
        uses      INTEGER DEFAULT 0,
        created   REAL DEFAULT 0,
        UNIQUE(scheme, host, port)
    );
    CREATE INDEX IF NOT EXISTS idx_state ON proxies(state);
    """

    def __init__(self, path: str, persist_credentials: bool = False) -> None:
        self.path = path
        self.persist_credentials = persist_credentials
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        if os.name != "nt" and path != ":memory:":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.executescript(self.SCHEMA)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.commit()

    def load_all(self) -> list[Proxy]:
        out: list[Proxy] = []
        with self.lock:
            for r in self.conn.execute("SELECT * FROM proxies"):
                p = Proxy(r["id"], r["scheme"], r["host"], r["port"],
                          r["user"] or "", r["password"] or "", r["region"] or "",
                          r["source"] or "", bool(r["enabled"]))
                p.state = r["state"] or "new"
                p.latency_ms = r["latency"] or 0.0
                p.score = r["score"] if r["score"] is not None else 0.5
                p.success = r["success"] or 0
                p.fail = r["fail"] or 0
                p.consec_fail = r["consec"] or 0
                p.last_ok = r["last_ok"] or 0.0
                p.last_check = r["last_chk"] or 0.0
                p.dead_until = r["dead_till"] or 0.0
                p.uses = r["uses"] or 0
                out.append(p)
        return out

    def upsert(self, entry: dict) -> Optional[int]:
        key = proxy_key(entry["scheme"], entry["host"], entry["port"])
        with self.lock:
            row = self.conn.execute(
                "SELECT id FROM proxies WHERE scheme=? AND host=? AND port=?",
                (entry["scheme"], entry["host"], int(entry["port"]))).fetchone()
            if row:
                return int(row["id"])
            cur = self.conn.execute(
                "INSERT INTO proxies(scheme,host,port,user,password,region,source,created)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (entry["scheme"], entry["host"], int(entry["port"]),
                 entry.get("user", "") if self.persist_credentials else "",
                 entry.get("password", "") if self.persist_credentials else "",
                 entry.get("region", ""), entry.get("source", ""), time.time()))
            self.conn.commit()
            return int(cur.lastrowid)

    def upsert_many(self, entries: list[dict]) -> list[int]:
        ids: list[int] = []
        for e in entries:
            pid = self.upsert(e)
            if pid is not None:
                ids.append(pid)
        return ids

    def delete(self, ids: list[int]) -> int:
        if not ids:
            return 0
        q = ",".join("?" for _ in ids)
        with self.lock:
            cur = self.conn.execute(f"DELETE FROM proxies WHERE id IN ({q})", tuple(ids))
            self.conn.commit()
            return cur.rowcount

    def set_enabled(self, pid: int, enabled: bool) -> bool:
        with self.lock:
            cur = self.conn.execute("UPDATE proxies SET enabled=? WHERE id=?",
                                    (1 if enabled else 0, pid))
            self.conn.commit()
            return cur.rowcount > 0

    def save_states(self, proxies: list[Proxy]) -> None:
        rows = [(p.state, p.latency_ms, p.score, p.success, p.fail, p.consec_fail,
                 p.last_ok, p.last_check, p.dead_until, p.uses, p.id) for p in proxies]
        with self.lock:
            self.conn.executemany(
                "UPDATE proxies SET state=?,latency=?,score=?,success=?,fail=?,consec=?,"
                "last_ok=?,last_chk=?,dead_till=?,uses=? WHERE id=?", rows)
            self.conn.commit()

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.commit()
                self.conn.close()
            except Exception:
                pass


# ───────────────────────────── 池 ─────────────────────────────

class ProxyPool:
    def __init__(self, cfg: dict, store: Store) -> None:
        p = cfg["pool"]
        self.strategy = p["strategy"]
        self.sticky_ttl = float(p["sticky_ttl"])
        self.allow_cold_start = bool(p["allow_cold_start"])
        self.max_dead_retry = int(p["max_dead_retry"])
        self.store = store
        self.proxies: list[Proxy] = store.load_all()
        self.by_id: dict[int, Proxy] = {x.id: x for x in self.proxies}
        self._sessions: dict[str, tuple[int, float]] = {}
        self._rr = 0
        self.dirty = False
        self.total_added = 0
        # 隐蔽性工程层：画像分桶 / 目标亲和 / 节律配额
        self.fingerprints = FingerprintBook()
        opt = cfg.get("hardening") or {}
        self.affinity = AffinityBook(
            affinity_ttl=float(opt.get("affinity_ttl", 900.0)),
            cooldown=float(opt.get("proxy_cooldown", 60.0)))
        self.rhythm = Rhythm(
            mu=float(opt.get("rhythm_mu", 1.6)),
            sigma=float(opt.get("rhythm_sigma", 0.6)),
            per_key_qps=float(opt.get("per_key_qps", 0.5)),
            global_qps=float(opt.get("global_qps", 2.0)))
        # 黑名单：注入/篡改坐实，永不再选（直到人工 clear_blacklist）
        self.blacklist: set[str] = set()
        for proxy in self.proxies:
            if not proxy.profile:
                proxy.profile = self.fingerprints.assign(proxy.key).name

    # —— 增删 ——
    def add_many(self, entries: list[dict]) -> tuple[int, int]:
        added = 0
        dup = 0
        for e in entries:
            k = proxy_key(e["scheme"], e["host"], e["port"])
            old = next((x for x in self.proxies if x.key == k), None)
            if old is not None:
                # Private source can rehydrate passwords without DB storage.
                if e.get("user"):
                    old.user = e["user"]
                    old.password = e.get("password", "")
                dup += 1
                continue
            pid = self.store.upsert(e)
            if pid is None:
                dup += 1
                continue
            p = Proxy(pid, e["scheme"], e["host"], int(e["port"]),
                      e.get("user", ""), e.get("password", ""),
                      e.get("region", ""), e.get("source", ""), True)
            p.profile = self.fingerprints.assign(p.key).name
            self.proxies.append(p)
            self.by_id[p.id] = p
            added += 1
        self.total_added += added
        self.dirty = True
        return added, dup

    def remove(self, ids: list[int]) -> int:
        n = self.store.delete(ids)
        idset = set(ids)
        self.proxies = [p for p in self.proxies if p.id not in idset]
        for i in idset:
            self.by_id.pop(i, None)
        for k, (pid, _) in list(self._sessions.items()):
            if pid in idset:
                self._sessions.pop(k, None)
        self.dirty = True
        return n

    # —— 评分 ——
    def _score(self, p: Proxy) -> float:
        lat = p.latency_ms if p.latency_ms > 0 else 3000.0
        lat_factor = max(0.0, min(1.0, 1.0 - lat / 5000.0))
        recency = 0.0
        if p.last_ok:
            age = time.time() - p.last_ok
            recency = max(0.0, min(1.0, 1.0 - age / 1800.0))
        s = 0.55 * p.ema_ok + 0.30 * lat_factor + 0.15 * recency
        # 体检结论直接进权重：degraded 打七折，unusable 打一折，黑名单归零
        if p.grade == "degraded":
            s *= 0.7
        elif p.grade == "unusable":
            s *= 0.1
        elif p.grade == "blacklist":
            s = 0.0
        if p.state == "dead":
            s *= 0.05
        elif p.state == "new":
            s = 0.5
        return max(0.001, min(1.0, s))

    def _backoff(self, consec: int) -> float:
        steps = max(0, consec - self.max_dead_retry)
        return min(60.0 * (2 ** steps), 1800.0)

    def report(self, p: Proxy, ok: bool, latency_ms: float = 0.0) -> None:
        p.uses += 1
        p.last_check = time.time()
        if ok:
            p.success += 1
            p.consec_fail = 0
            p.last_ok = p.last_check
            p.state = "alive"
            p.dead_until = 0.0
            if latency_ms > 0:
                p.latency_ms = latency_ms if p.latency_ms <= 0 else (
                    0.7 * p.latency_ms + 0.3 * latency_ms)
            p.ema_ok = 0.7 * p.ema_ok + 0.3 * 1.0
        else:
            p.fail += 1
            p.consec_fail += 1
            p.ema_ok = 0.7 * p.ema_ok + 0.0 * 0.3
            if p.consec_fail >= self.max_dead_retry:
                p.state = "dead"
                p.dead_until = time.time() + self._backoff(p.consec_fail)
            elif p.state == "new":
                p.state = "probation"
        p.score = self._score(p)
        self.dirty = True

    def apply_audit(self, p: Proxy, record: dict) -> dict:
        """把五判据结论写回池子；注入/篡改坐实的代理永久移出选路。"""
        p.grade = record.get("grade", "")
        p.audit = record
        if p.grade == "blacklist":
            self.blacklist.add(p.key)
            p.enabled = False
            self.store.set_enabled(p.id, False)
            p.state = "dead"
            p.dead_until = time.time() + 86400.0
        elif p.state == "new" and p.grade in ("usable", "degraded"):
            p.state = "alive"
        p.score = self._score(p)
        self.dirty = True
        return {"id": p.id, "grade": p.grade, "score": p.score,
                "blacklist_size": len(self.blacklist)}

    def clear_blacklist(self, keys: Optional[list[str]] = None) -> int:
        """人工复核后放行：keys 为空则整表清空。"""
        if keys is None:
            freed = list(self.blacklist)
            self.blacklist.clear()
        else:
            freed = [k for k in keys if k in self.blacklist]
            for k in freed:
                self.blacklist.discard(k)
        for p in self.proxies:
            if p.key in freed:
                p.enabled = True
                self.store.set_enabled(p.id, True)
                p.state = "new"
                p.dead_until = 0.0
                p.grade = ""
                p.score = 0.5
        self.dirty = True
        return len(freed)

    # —— 选路 ——
    def candidates(self) -> list[Proxy]:
        now = time.time()
        pool = [p for p in self.proxies
                if p.enabled and p.key not in self.blacklist
                and p.grade != "blacklist"]
        alive = [p for p in pool if p.state == "alive" and p.dead_until <= now]
        if alive:
            return alive
        prob = [p for p in pool if p.state == "probation" and p.dead_until <= now]
        if prob:
            return prob
        revive = [p for p in pool if p.state == "dead" and p.dead_until <= now]
        if revive:
            return revive
        if self.allow_cold_start:
            return [p for p in pool if p.state == "new"]
        return []

    def _select(self, cand: list[Proxy], strategy: str) -> Proxy:
        if strategy in ("round_robin",):
            self._rr = (self._rr + 1) % len(cand)
            return cand[self._rr]
        if strategy in ("fastest",):
            top = sorted(cand, key=lambda p: p.latency_ms or 1e9)[:5]
            return random.choice(top)
        if strategy in ("random",):
            return random.choice(cand)
        # weighted_random
        weights = [max(p.score, 0.001) ** 2 for p in cand]
        total = sum(weights)
        r = random.uniform(0, total)
        acc = 0.0
        for p, w in zip(cand, weights):
            acc += w
            if acc >= r:
                return p
        return cand[-1]

    def pick(self, strategy: Optional[str] = None,
             session_key: Optional[str] = None,
             exclude_ids: Optional[set[int]] = None,
             host: Optional[str] = None,
             affinity: bool = True) -> Optional[Proxy]:
        """Select an eligible proxy; a retry must not return one already attempted.

        host 非空时叠加两件事：
          ① 单出口冷却——冷却窗口内不重复承接同一目标域，防单 IP 高频（默认生效）；
          ② 目标域亲和——窗口内复用同一出口（affinity=True 时生效）。
        affinity 只给「有登录态/有流程连续性」的场合用；网关裸请求传 False，
        否则同一目标域的并发请求会全部压到一条线上。
        """
        excluded = exclude_ids or set()
        now = time.time()
        if session_key:
            hit = self._sessions.get(session_key)
            if hit and hit[1] > now and hit[0] not in excluded:
                p = self.by_id.get(hit[0])
                if p and p.enabled and p.state != "dead" and p.key not in self.blacklist:
                    return p
        if host and affinity:
            bound = self.affinity.affinity(host)
            if bound:
                p = next((x for x in self.proxies if x.key == bound), None)
                if (p and p.enabled and p.state != "dead" and p.id not in excluded
                        and p.key not in self.blacklist):
                    self.affinity.touch(host, p.key)
                    if session_key:
                        self._sessions[session_key] = (p.id, now + self.sticky_ttl)
                    return p
        cand = [p for p in self.candidates() if p.id not in excluded]
        if host and cand:
            cooled = [p for p in cand if not self.affinity.cooling(host, p.key)]
            if cooled:
                cand = cooled
        if not cand:
            return None
        p = self._select(cand, strategy or self.strategy)
        if host:
            if affinity:
                self.affinity.bind(host, p.key)
            self.affinity.touch(host, p.key)
        if session_key:
            self._sessions[session_key] = (p.id, now + self.sticky_ttl)
        return p

    def invalidate_session(self, session_key: str, proxy_id: Optional[int] = None) -> bool:
        """Release only the expected binding, avoiding another worker's newer session."""
        hit = self._sessions.get(session_key)
        if not hit or (proxy_id is not None and hit[0] != proxy_id):
            return False
        self._sessions.pop(session_key, None)
        return True

    def purge_sessions(self) -> int:
        now = time.time()
        dead = [k for k, (_, exp) in self._sessions.items() if exp <= now]
        for k in dead:
            self._sessions.pop(k, None)
        return len(dead)

    # —— 统计 ——
    def stats(self) -> dict:
        by_state: dict[str, int] = {}
        for p in self.proxies:
            by_state[p.state] = by_state.get(p.state, 0) + 1
        now = time.time()
        alive = [p for p in self.proxies
                 if p.enabled and p.state == "alive" and p.dead_until <= now]
        lat = sorted(p.latency_ms for p in alive if p.latency_ms > 0)
        p50 = lat[len(lat) // 2] if lat else 0.0
        p90 = lat[int(len(lat) * 0.9)] if lat else 0.0

        def distinct_public_ipv4(items: list[Proxy]) -> int:
            # A proxy endpoint is not a distinct egress IP. Count literal,
            # globally routable IPv4 addresses only; hostnames are unknown.
            hosts: set[str] = set()
            for item in items:
                try:
                    address = ipaddress.IPv4Address(item.host)
                except ipaddress.AddressValueError:
                    continue
                if address.is_global:
                    hosts.add(str(address))
            return len(hosts)

        recently_verified = [p for p in alive
                             if p.last_ok > 0 and 0 <= now - p.last_ok <= 300]
        return {
            "total": len(self.proxies),
            "unique_public_ipv4_total": distinct_public_ipv4(self.proxies),
            "unique_public_ipv4_alive": distinct_public_ipv4(alive),
            "unique_public_ipv4_verified_5m": distinct_public_ipv4(recently_verified),
            "enabled": sum(1 for p in self.proxies if p.enabled),
            "by_state": by_state,
            "alive": len(alive),
            "latency_p50_ms": round(p50, 1),
            "latency_p90_ms": round(p90, 1),
            "sessions": len(self._sessions),
            "strategy": self.strategy,
            "total_uses": sum(p.uses for p in self.proxies),
            "total_success": sum(p.success for p in self.proxies),
            "total_fail": sum(p.fail for p in self.proxies),
            "blacklist": len(self.blacklist),
            "by_grade": self._by_grade(),
            "fingerprints": self._by_profile(),
            "affinity": self.affinity.stats(),
        }

    def _by_grade(self) -> dict:
        tally: dict[str, int] = {}
        for p in self.proxies:
            key = p.grade or "unchecked"
            tally[key] = tally.get(key, 0) + 1
        return tally

    def _by_profile(self) -> dict:
        tally: dict[str, int] = {}
        for p in self.proxies:
            key = p.profile or "unassigned"
            tally[key] = tally.get(key, 0) + 1
        return tally

    def alive_list(self) -> list[dict]:
        now = time.time()
        return [p.to_dict() for p in self.proxies
                if p.enabled and p.state == "alive" and p.dead_until <= now]


# ───────────────────────────── 上游建连 ─────────────────────────────

async def _socks5_handshake(r: asyncio.StreamReader, w: asyncio.StreamWriter,
                            host: str, port: int, user: str, password: str) -> None:
    """SOCKS5 客户端握手 + CONNECT。失败抛异常。"""
    methods = b"\x05\x02\x00\x02" if user else b"\x05\x01\x00"
    w.write(methods)
    await w.drain()
    resp = await r.readexactly(2)
    if resp[0] != 0x05:
        raise ConnectionError("socks5: bad version")
    method = resp[1]
    if method == 0x02:
        if not user:
            raise ConnectionError("socks5: server requires auth")
        ub = user.encode()
        pb = password.encode()
        w.write(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        await w.drain()
        ar = await r.readexactly(2)
        if ar[1] != 0x00:
            raise ConnectionError("socks5: auth failed")
    elif method != 0x00:
        raise ConnectionError("socks5: no acceptable method")
    # CONNECT
    try:
        socket.inet_aton(host)
        addr = b"\x01" + socket.inet_aton(host)
    except OSError:
        hb = host.encode("idna") if host.isascii() is False else host.encode()
        if len(hb) > 255:
            raise ConnectionError("socks5: host too long")
        addr = b"\x03" + bytes([len(hb)]) + hb
    w.write(b"\x05\x01\x00" + addr + int(port).to_bytes(2, "big"))
    await w.drain()
    rep = await r.readexactly(4)
    if rep[1] != 0x00:
        raise ConnectionError(f"socks5: connect failed code={rep[1]}")
    atyp = rep[3]
    if atyp == 0x01:
        await r.readexactly(4 + 2)
    elif atyp == 0x03:
        n = await r.readexactly(1)
        await r.readexactly(n[0] + 2)
    elif atyp == 0x04:
        await r.readexactly(16 + 2)


async def open_tunnel(proxy: Proxy, host: str, port: int,
                      timeout: float = 15.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """在 proxy 之上建立一条到 host:port 的字节隧道。返回已就绪的 (reader, writer)。"""
    if proxy.scheme in ("socks5", "socks4"):
        r, w = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout)
        try:
            await asyncio.wait_for(
                _socks5_handshake(r, w, host, port, proxy.user, proxy.password), timeout)
        except Exception:
            w.close()
            raise
        return r, w
    # HTTP / HTTPS 代理走 CONNECT
    if proxy.scheme == "https":
        ctx = verified_tls_context()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port, ssl=ctx,
                                    server_hostname=proxy.host), timeout)
    else:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout)
    try:
        lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
        if proxy.user:
            lines.append(f"Proxy-Authorization: {basic_header(proxy.user, proxy.password)}")
        lines.append("")
        lines.append("")
        w.write("\r\n".join(lines).encode("latin-1"))
        await w.drain()
        status_line, _ = await asyncio.wait_for(read_head(r), timeout)
        parts = status_line.split()
        if len(parts) < 2 or not parts[1].startswith("2"):
            raise ConnectionError(f"CONNECT rejected: {status_line[:80]}")
    except Exception:
        w.close()
        raise
    return r, w


async def fetch_via_proxy(proxy: Proxy, url: str, timeout: float = 8.0,
                          max_bytes: int = 32768,
                          profile=None) -> tuple[int, list, bytes]:
    """通过 proxy 取一个 URL，返回 (status, headers, body_prefix)。

    走 poolopt.proxy_fetch：按出口画像生成头序，https 目标做 CONNECT+TLS，
    socks5 目标做 SOCKS5 握手（含域名远端解析），不再共用一把全局 UA。
    """
    headers = []
    if profile is not None:
        headers = [("User-Agent", profile.ua), ("Accept", "*/*"),
                   ("Accept-Language", profile.lang),
                   ("Accept-Encoding", "gzip, deflate"),
                   ("Upgrade-Insecure-Requests", "1")]
        headers += [(canonical(k), v) for k, v in profile.extra.items()]
    else:
        headers = [("User-Agent", DEFAULT_UA), ("Accept", "*/*"),
                   ("Accept-Language", "en-US,en;q=0.9"),
                   ("Accept-Encoding", "gzip, deflate")]
    result = await poolopt.proxy_fetch(proxy, url, timeout=timeout,
                                       headers=headers, max_body=max_bytes,
                                       profile=profile)
    return result["status"], result["headers"], result["body"]


async def _read_simple_response(r: asyncio.StreamReader,
                                max_bytes: int) -> tuple[int, list, bytes]:
    status_line, headers = await read_head(r)
    parts = status_line.split()
    try:
        status = int(parts[1])
    except Exception:
        status = 0
    body = b""
    if 200 <= status < 400:
        try:
            framing = any(k.lower() in ("content-length", "transfer-encoding")
                          for k, _ in headers)
            if framing:
                body = await read_body(r, headers, limit=max_bytes, strict=False)
            elif status not in (204, 304):
                # HTTP/1.0 or Connection: close responses may omit length.
                body = await r.read(max_bytes)
        except Exception:
            body = b""
    return status, headers, body


# ───────────────────────────── 健康检查 ─────────────────────────────

class Checker:
    def __init__(self, cfg: dict, pool: ProxyPool) -> None:
        c = cfg["checker"]
        self.enabled = bool(c["enabled"])
        self.interval = float(c["interval"])
        self.concurrency = int(c["concurrency"])
        self.timeout = float(c["timeout"])
        self.targets = list(c["targets"])
        self.expect = c.get("expect_contains", "") or ""
        self.max_bytes = int(c["max_bytes"])
        self.content_check = bool(c.get("content_check", True))
        self.pool = pool
        self._sem = asyncio.Semaphore(self.concurrency)
        self._rr_target = 0
        hard = (cfg.get("hardening") or {})
        self.gate = AnonymityGate(
            self.targets, timeout=self.timeout, max_body=self.max_bytes,
            fingerprint=self.pool.fingerprints,
            port_scope_host=str(hard.get("port_scope_host", "example.com")),
            port_scope_ports=tuple(int(x) for x in hard.get(
                "port_scope_ports", [22, 25, 6379])))

    def _next_target(self) -> str:
        if not self.targets:
            return "http://www.gstatic.com/generate_204"
        t = self.targets[self._rr_target % len(self.targets)]
        self._rr_target += 1
        return t

    async def check_one(self, p: Proxy, target: Optional[str] = None) -> tuple[bool, float, str]:
        target = target or self._next_target()
        async with self._sem:
            # 体检也走出口自己的画像，不要让 M 条代理共用一把 UA 被聚成一堆
            profile = self.pool.fingerprints.by_name(p.profile)
            t0 = time.monotonic()
            try:
                status, headers, body = await fetch_via_proxy(
                    p, target, timeout=self.timeout, max_bytes=self.max_bytes,
                    profile=profile)
                latency = (time.monotonic() - t0) * 1000
                ok = 200 <= status < 400
                reason = f"status={status}"
                if ok and self.expect:
                    if self.expect.encode("utf-8") not in body:
                        ok = False
                        reason = f"status={status} 但缺少期望串 {self.expect!r}"
                elif ok and status == 200 and not body:
                    ok = False
                    reason = "status=200 但响应体为空（疑似拦截页）"
                elif ok and self.content_check:
                    # L2 内容一致性：与直连基线比 sha256，防「能连但返回假页」
                    same, why = await self.gate.content_ok(p, target)
                    if not same:
                        ok = False
                        reason = f"status={status} 内容与直连基线不一致 ({why})"
                self.pool.report(p, ok, latency)
                if not ok:
                    log("debug", "check fail %s reason=%s", p.label, reason)
                return ok, latency, reason
            except asyncio.TimeoutError:
                self.pool.report(p, False, 0.0)
                return False, 0.0, "timeout"
            except Exception as e:
                self.pool.report(p, False, 0.0)
                return False, 0.0, type(e).__name__

    async def deep_check(self, p: Proxy) -> dict:
        """五判据全量体检：透明性 / 注入 / 篡改 / 一致性 / 端口面。"""
        async with self._sem:
            record = await self.gate.audit(p, deep=True)
        self.pool.apply_audit(p, record)
        return record

    async def deep_check_many(self, proxies: list[Proxy]) -> dict:
        if not proxies:
            return {"checked": 0, "usable": 0, "degraded": 0,
                    "blacklist": 0, "unusable": 0}
        results = await asyncio.gather(
            *[self.deep_check(p) for p in proxies], return_exceptions=True)
        tally = {"checked": len(proxies), "usable": 0, "degraded": 0,
                 "blacklist": 0, "unusable": 0, "error": 0}
        for record in results:
            if isinstance(record, Exception):
                tally["error"] += 1
                continue
            tally[record.get("grade", "unusable")] = \
                tally.get(record.get("grade", "unusable"), 0) + 1
        return tally

    async def check_many(self, proxies: list[Proxy]) -> dict:
        if not proxies:
            return {"checked": 0, "ok": 0, "fail": 0}
        results = await asyncio.gather(*[self.check_one(p) for p in proxies],
                                       return_exceptions=True)
        ok = 0
        fail = 0
        for r in results:
            if isinstance(r, Exception):
                fail += 1
            elif r[0]:
                ok += 1
            else:
                fail += 1
        return {"checked": len(proxies), "ok": ok, "fail": fail}

    async def check_all(self, include_dead: bool = True) -> dict:
        now = time.time()
        if include_dead:
            targets = [p for p in self.pool.proxies
                       if p.enabled and (p.state != "dead" or p.dead_until <= now)]
        else:
            targets = [p for p in self.pool.proxies if p.enabled and p.state != "dead"]
        return await self.check_many(targets)


# ───────────────────────────── 本地网关（正向代理） ─────────────────────────────

class Gateway:
    def __init__(self, cfg: dict, pool: ProxyPool, checker: Checker) -> None:
        g = cfg["gateway"]
        self.host = g["host"]
        self.port = int(g["port"])
        self.auth = g["auth"] or ""
        self.max_retry = int(g["max_retry"])
        self.retry_on_status = set(int(x) for x in g.get("retry_on_status", []))
        self.direct_fallback = bool(g["direct_fallback"])
        self.connect_timeout = float(g["connect_timeout"])
        self.idle_timeout = float(g["idle_timeout"])
        self.rhythm_on = bool(g.get("rhythm_enabled", True))
        self.shape_headers = bool(g.get("shape_headers", True))
        self.pool = pool
        self.checker = checker
        self.stats = {"conn": 0, "ok": 0, "fail": 0, "retry": 0, "direct": 0}

    def _auth_ok(self, headers: list[tuple[str, str]]) -> bool:
        if not self.auth:
            return True
        want_user, _, want_pass = self.auth.partition(":")
        got = hget(headers, "proxy-authorization")
        if not got:
            return False
        u, p = parse_basic(got)
        return u == want_user and p == want_pass

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        self.stats["conn"] += 1
        try:
            first, headers = await asyncio.wait_for(read_head(reader), self.idle_timeout)
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            return

        if not self._auth_ok(headers):
            body = b"proxy authentication required"
            writer.write(http_response(
                407, "Proxy Authentication Required",
                [("Proxy-Authenticate", 'Basic realm="proxypool"'),
                 ("Content-Type", "text/plain"),
                 ("Connection", "close")], body))
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass
            self.stats["fail"] += 1
            return

        parts = first.split()
        if len(parts) < 2:
            await self._err(writer, 400, "Bad Request")
            return
        method = parts[0].upper()
        try:
            if method == "CONNECT":
                await self._do_connect(parts[1], reader, writer)
            else:
                await self._do_forward(first, headers, reader, writer)
        except Exception as e:
            log("debug", "gateway error: %r", e)
            self.stats["fail"] += 1
            await self._err(writer, 502, "Bad Gateway")

    async def _err(self, writer: asyncio.StreamWriter, code: int, reason: str) -> None:
        try:
            writer.write(http_response(code, reason,
                                       [("Content-Type", "text/plain"),
                                        ("Connection", "close")], reason.encode()))
            await writer.drain()
            writer.close()
        except Exception:
            pass

    async def _open_upstream(self, proxy: Proxy, host: str, port: int):
        t0 = time.monotonic()
        r, w = await open_tunnel(proxy, host, port, self.connect_timeout)
        return r, w, (time.monotonic() - t0) * 1000

    async def _do_connect(self, authority: str, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        host, _, port_s = authority.partition(":")
        try:
            port = int(port_s or "443")
        except ValueError:
            await self._err(writer, 400, "Bad CONNECT target")
            return

        attempts = self.max_retry + 1
        last_err = "no proxy available"
        attempted_ids: set[int] = set()
        for i in range(attempts):
            # host 参与选路：单出口冷却防单 IP 高频；网关裸请求不绑亲和
            # （绑了会把同域并发全压到一条线，A/B 轮换就失效了）
            p = self.pool.pick(session_key=None, exclude_ids=attempted_ids,
                               host=host, affinity=False)
            if p is None:
                break
            attempted_ids.add(p.id)
            try:
                if self.rhythm_on:
                    await self.pool.rhythm.wait(host, p.key)
                ur, uw, lat = await self._open_upstream(p, host, port)
            except Exception as e:
                last_err = f"{p.label}: {type(e).__name__}"
                self.pool.report(p, False)
                self.stats["retry"] += 1
                if i < attempts - 1:
                    log("debug", "CONNECT retry after %s (%s)", last_err, p.label)
                    continue
                break
            self.pool.report(p, True, lat)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            self.stats["ok"] += 1
            await asyncio.gather(
                _pipe(reader, uw),
                _pipe(ur, writer),
                return_exceptions=True)
            return

        if self.direct_fallback:
            try:
                dr, dw = await asyncio.wait_for(
                    asyncio.open_connection(host, port), self.connect_timeout)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                self.stats["direct"] += 1
                await asyncio.gather(_pipe(reader, dw), _pipe(dr, writer),
                                     return_exceptions=True)
                return
            except Exception:
                pass
        self.stats["fail"] += 1
        log("warn", "CONNECT %s 全部失败: %s", authority, last_err)
        await self._err(writer, 502, "Bad Gateway: no healthy upstream proxy")

    async def _do_forward(self, first: str, headers: list[tuple[str, str]],
                          reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        parts = first.split()
        url = parts[1]
        if not url.lower().startswith("http://") and not url.lower().startswith("https://"):
            # origin-form（客户端把我们当普通服务器用）—— 不支持的场景明确拒绝
            host = hget(headers, "host")
            if host:
                url = f"http://{host}{url}"
            else:
                await self._err(writer, 400, "Absolute URI required")
                return
        u = urllib.parse.urlsplit(url)
        if not u.hostname:
            await self._err(writer, 400, "Bad Request URI")
            return
        try:
            body = await asyncio.wait_for(read_body(reader, headers, limit=MAX_BODY),
                                          timeout=self.idle_timeout)
        except BodyTooLarge:
            await self._err(writer, 413, "Content Too Large")
            return
        except asyncio.TimeoutError:
            await self._err(writer, 408, "Request Timeout")
            return
        except (MalformedBody, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            await self._err(writer, 400, "Malformed Request Body")
            return

        # Writes may already have reached the server when a response fails.
        retryable = parts[0].upper() in ("GET", "HEAD", "OPTIONS")
        attempts = self.max_retry + 1 if retryable else 1
        attempted = False
        attempted_ids: set[int] = set()
        for i in range(attempts):
            p = self.pool.pick(exclude_ids=attempted_ids, host=u.hostname, affinity=False)
            if p is None:
                break
            attempted_ids.add(p.id)
            try:
                attempted = True
                if self.rhythm_on:
                    await self.pool.rhythm.wait(u.hostname, p.key)
                status, resp, lat = await self._forward_once(p, u, parts[0], headers, body)
            except Exception as e:
                self.pool.report(p, False)
                self.stats["retry"] += 1
                log("debug", "forward retry after %s (%s)", type(e).__name__, p.label)
                if i < attempts - 1:
                    continue
                break
            if retryable and status in self.retry_on_status and i < attempts - 1:
                self.pool.report(p, False)
                self.stats["retry"] += 1
                continue
            self.pool.report(p, 200 <= status < 400, lat)
            self.stats["ok"] += 1
            writer.write(resp)
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass
            return

        if self.direct_fallback and (retryable or not attempted):
            try:
                resp = await self._direct_forward(u, parts[0], headers, body)
                self.stats["direct"] += 1
                writer.write(resp)
                await writer.drain()
                writer.close()
                return
            except Exception:
                pass
        self.stats["fail"] += 1
        await self._err(writer, 502, "Bad Gateway: no healthy upstream proxy")

    async def _forward_once(self, p: Proxy, u, method: str,
                            headers: list[tuple[str, str]],
                            body: bytes) -> tuple[int, bytes, float]:
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        t0 = time.monotonic()
        profile = self.pool.fingerprints.by_name(p.profile)

        # 上游需要建隧道的情形：socks5 或目标是 https
        need_tunnel = p.scheme in ("socks5", "socks4") or u.scheme == "https"
        if need_tunnel:
            r, w = await open_tunnel(p, host, port, self.connect_timeout)
            try:
                if u.scheme == "https":
                    ctx = tls_context(profile)
                    await asyncio.wait_for(w.start_tls(ctx, server_hostname=host),
                                           self.connect_timeout)
                req_line = f"{method} {path} HTTP/1.1"
                out = self._rebuild_headers(req_line, headers, u.netloc, body,
                                            strip_proxy_auth=True, profile=profile)
                w.write(out)
                await w.drain()
                resp = await self._relay_response(r, w, method)
                lat = (time.monotonic() - t0) * 1000
                return self._peek_status(resp), resp, lat
            finally:
                try:
                    w.close()
                except Exception:
                    pass

        # 明文 HTTP 走 absolute-form
        r, w = await asyncio.wait_for(
            asyncio.open_connection(p.host, p.port), self.connect_timeout)
        try:
            req_line = f"{method} {urllib.parse.urlunsplit(u)} HTTP/1.1"
            out = self._rebuild_headers(req_line, headers, u.netloc, body,
                                        strip_proxy_auth=True, profile=profile)
            if p.user:
                out = out.replace(b"\r\n\r\n",
                                  f"\r\nProxy-Authorization: {basic_header(p.user, p.password)}"
                                  "\r\n\r\n".encode("latin-1"), 1)
            w.write(out)
            await w.drain()
            resp = await self._relay_response(r, w, method)
            lat = (time.monotonic() - t0) * 1000
            return self._peek_status(resp), resp, lat
        finally:
            try:
                w.close()
            except Exception:
                pass

    def _rebuild_headers(self, req_line: str, headers: list[tuple[str, str]],
                         host_header: str, body: bytes,
                         strip_proxy_auth: bool = True,
                         profile=None) -> bytes:
        # The body has been decoded; never forward its original framing.
        # Otherwise a de-chunked request can retain Transfer-Encoding: chunked
        # or a truncated Content-Length, making the next hop misparse it.
        skip = {"proxy-connection", "connection", "keep-alive",
                "proxy-authorization", "te", "trailer", "upgrade",
                "transfer-encoding", "content-length"}
        for key, value in headers:
            if key.lower() == "connection":
                skip.update(part.strip().lower() for part in value.split(","))
        if not strip_proxy_auth:
            skip.discard("proxy-authorization")

        if profile is not None and self.shape_headers:
            # 按出口画像重排头序并补默认头：同一出口永远同一画像，跨请求不漂移
            kept = [(k, v) for k, v in headers if k.lower() not in skip]
            shaped = shape_request(profile, kept, host_header)
            # Connection 挪到最后：真实客户端把 Content-Length 排在 Connection 之前
            shaped = [(k, v) for k, v in shaped if k.lower() != "connection"]
            lines = [req_line] + [f"{k}: {v}" for k, v in shaped]
        else:
            lines = [req_line]
            seen_host = False
            for k, v in headers:
                low = k.lower()
                if low in skip:
                    continue
                if low == "host":
                    lines.append(f"Host: {host_header}")
                    seen_host = True
                    continue
                lines.append(f"{k}: {v}")
            if not seen_host:
                lines.append(f"Host: {host_header}")
            lines.append("Connection: close")

        method = req_line.split(" ", 1)[0].upper()
        framed = any(k.lower() in ("content-length", "transfer-encoding")
                     for k, _ in headers)
        if body or framed or method in ("POST", "PUT", "PATCH", "DELETE"):
            # Content-Length 追加在最后：真实客户端也常在末尾带它
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    async def _relay_response(self, r: asyncio.StreamReader,
                              w: asyncio.StreamWriter,
                              request_method: str = "GET") -> bytes:
        """Buffer an upstream response only if complete and within the configured bound.

        Timeout / reset / overflow must fail closed; returning a truncated
        HTTP response can make a client treat an incomplete download as success.
        """
        buf = bytearray()
        while True:
            data = await asyncio.wait_for(r.read(CHUNK), self.idle_timeout)
            if not data:
                response = bytes(buf)
                ensure_complete_upstream_response(response, request_method)
                return response
            if len(buf) + len(data) > MAX_RESPONSE_BYTES:
                raise BodyTooLarge("upstream response exceeds bounded buffer")
            buf.extend(data)

    @staticmethod
    def _peek_status(resp: bytes) -> int:
        try:
            line = resp.split(b"\r\n", 1)[0].decode("latin-1")
            return int(line.split()[1])
        except Exception:
            return 0

    async def _direct_forward(self, u, method: str,
                              headers: list[tuple[str, str]], body: bytes) -> bytes:
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        ctx = None
        if u.scheme == "https":
            ctx = verified_tls_context()
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host
                                    if ctx else None), self.connect_timeout)
        try:
            out = self._rebuild_headers(f"{method} {path} HTTP/1.1", headers,
                                        u.netloc, body, strip_proxy_auth=True)
            w.write(out)
            await w.drain()
            return await self._relay_response(r, w, method)
        finally:
            try:
                w.close()
            except Exception:
                pass


# ───────────────────────────── HTTP API ─────────────────────────────

class ApiServer:
    def __init__(self, cfg: dict, app: "App") -> None:
        a = cfg["api"]
        self.host = a["host"]
        self.port = int(a["port"])
        self.token = a["token"] or ""
        self.request_timeout = float(a.get("request_timeout", 30.0))
        self.app = app

    def _auth_ok(self, headers: list[tuple[str, str]], query: dict) -> bool:
        if not self.token:
            return True
        got = hget(headers, "authorization")
        if got.startswith("Bearer "):
            if got[7:].strip() == self.token:
                return True
        if (query.get("token", [""])[0]) == self.token:
            return True
        return False

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        try:
            first, headers = await asyncio.wait_for(read_head(reader), self.request_timeout)
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            return
        parts = first.split()
        if len(parts) < 2:
            await self._send(writer, json_response({"error": "bad request"}, 400))
            return
        method = parts[0].upper()
        u = urllib.parse.urlsplit(parts[1])
        path = u.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(u.query)
        if not self._auth_ok(headers, query):
            await self._send(writer, json_response({"error": "unauthorized"}, 401))
            return
        try:
            body = await asyncio.wait_for(read_body(reader, headers),
                                          timeout=self.request_timeout)
        except BodyTooLarge:
            await self._send(writer, json_response({"error": "payload_too_large"}, 413))
            return
        except asyncio.TimeoutError:
            await self._send(writer, json_response({"error": "request_timeout"}, 408))
            return
        except (MalformedBody, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            await self._send(writer, json_response({"error": "invalid_body_framing"}, 400))
            return
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(payload, dict):
                raise ValueError("JSON payload must be an object")
        except (ValueError, UnicodeDecodeError):
            await self._send(writer, json_response({"error": "invalid_json"}, 400))
            return

        try:
            resp = await self._route(method, path, query, payload)
        except Exception as e:
            log("error", "api %s %s -> %r", method, path, e)
            resp = json_response({"error": f"{type(e).__name__}: {e}"}, 500)
        await self._send(writer, resp)

    async def _send(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        try:
            writer.write(data)
            await writer.drain()
            writer.close()
        except Exception:
            pass

    async def _route(self, method: str, path: str, query: dict,
                     payload: dict) -> bytes:
        pool = self.app.pool

        if path in ("/", "/index"):
            return self._html()

        if path == "/health":
            return json_response({"ok": True, "version": VERSION,
                                  "uptime_s": int(time.time() - self.app.started_at)})

        if path == "/get" or path.startswith("/get/"):
            session = query.get("session", [None])[0]
            if path.startswith("/get/"):
                session = urllib.parse.unquote(path[len("/get/"):])
            strategy = query.get("strategy", [None])[0]
            fmt = query.get("format", ["json"])[0].lower()
            try:
                excluded = {int(x) for x in query.get("exclude", [""])[0].split(",") if x}
                if len(excluded) > 32 or any(x <= 0 for x in excluded):
                    raise ValueError("invalid exclusion list")
            except ValueError:
                return json_response({"error": "invalid_exclude_ids"}, 400)
            p = pool.pick(strategy=strategy, session_key=session, exclude_ids=excluded,
                          host=(query.get("host", [None])[0] or None),
                          affinity=(query.get("affinity", ["1"])[0] not in ("0", "false")))
            if p is None:
                return json_response({"error": "no_proxy_available"}, 503)
            if (p.user or p.password) and not self.token:
                return json_response({"error": "api_token_required_for_credentialed_proxy"}, 403)
            return self._format(p, fmt)

        if path == "/sessions/invalidate" and method == "POST":
            session = payload.get("session")
            if not isinstance(session, str) or not session or len(session) > 256:
                return json_response({"error": "invalid_session"}, 400)
            try:
                proxy_id = payload.get("proxy_id")
                proxy_id = int(proxy_id) if proxy_id is not None else None
            except (ValueError, TypeError):
                return json_response({"error": "invalid_proxy_id"}, 400)
            return json_response({"invalidated": pool.invalidate_session(session, proxy_id)})

        if path == "/all":
            only_alive = query.get("alive", ["0"])[0] in ("1", "true", "yes")
            items = pool.alive_list() if only_alive else [p.to_dict() for p in pool.proxies]
            return json_response({"count": len(items), "proxies": items})

        if path == "/stats":
            return json_response(pool.stats())

        # TLS endpoints are not proxies: never mix into /get, /all, checker or gateway.
        if path == "/direct/stats" and method == "GET":
            return json_response(self.app.direct_nodes.stats())

        if path == "/direct/all" and method == "GET":
            host = query.get("host", [None])[0]
            nodes = self.app.direct_nodes.all(host)
            return json_response({"count": len(nodes), "nodes": nodes,
                                  "fresh": self.app.direct_nodes.is_fresh(),
                                  "live_verified": False})

        if path == "/direct/get" and method == "GET":
            host = query.get("host", [""])[0]
            if not host or host not in self.app.direct_nodes.allowed_hosts:
                return json_response({"error": "host_not_allowed"}, 400)
            node = self.app.direct_nodes.get(host)
            if node is None:
                return json_response({"error": "no_fresh_direct_node"}, 503)
            return json_response(node)

        if path == "/direct/reload" and method == "POST":
            return json_response(self.app.direct_nodes.reload())

        if path == "/sources" and method == "GET":
            return json_response(self.app.public_sources.status())

        if path == "/sources/refresh" and method == "POST":
            name = payload.get("name")
            if name is not None and not isinstance(name, str):
                return json_response({"error": "invalid_source_name"}, 400)
            result = await self.app.public_sources.refresh(name=name)
            return json_response(result, 404 if "error" in result else 200)

        if path == "/metrics":
            s = pool.stats()
            gw = self.app.gateway.stats if self.app.gateway else {}
            lines = [
                "# HELP proxy_pool_total 池中代理总数",
                "# TYPE proxy_pool_total gauge",
                f"proxy_pool_total {s['total']}",
                "# TYPE proxy_pool_alive gauge",
                f"proxy_pool_alive {s['alive']}",
                "# TYPE proxy_pool_unique_public_ipv4_total gauge",
                f"proxy_pool_unique_public_ipv4_total {s['unique_public_ipv4_total']}",
                "# TYPE proxy_pool_unique_public_ipv4_alive gauge",
                f"proxy_pool_unique_public_ipv4_alive {s['unique_public_ipv4_alive']}",
                "# TYPE proxy_pool_unique_public_ipv4_verified_5m gauge",
                f"proxy_pool_unique_public_ipv4_verified_5m {s['unique_public_ipv4_verified_5m']}",
                "# TYPE proxy_pool_disabled gauge",
                f"proxy_pool_disabled {s['total'] - s['enabled']}",
                "# TYPE proxy_pool_latency_p50_ms gauge",
                f"proxy_pool_latency_p50_ms {s['latency_p50_ms']}",
                "# TYPE proxy_pool_latency_p90_ms gauge",
                f"proxy_pool_latency_p90_ms {s['latency_p90_ms']}",
                "# TYPE proxy_pool_uses_total counter",
                f"proxy_pool_uses_total {s['total_uses']}",
                "# TYPE proxy_pool_fail_total counter",
                f"proxy_pool_fail_total {s['total_fail']}",
                "# TYPE proxy_gateway_conn_total counter",
                f"proxy_gateway_conn_total {gw.get('conn', 0)}",
                "# TYPE proxy_gateway_retry_total counter",
                f"proxy_gateway_retry_total {gw.get('retry', 0)}",
                "# TYPE proxy_pool_blacklist gauge",
                f"proxy_pool_blacklist {s.get('blacklist', 0)}",
                "# TYPE proxy_pool_grade gauge",
            ]
            for grade, count in sorted(s.get("by_grade", {}).items()):
                lines.append(f'proxy_pool_grade{{grade="{grade}"}} {count}')
            lines.append("# TYPE proxy_pool_fingerprint_bucket gauge")
            for name, count in sorted(s.get("fingerprints", {}).items()):
                lines.append(f'proxy_pool_fingerprint_bucket{{profile="{name}"}} {count}')
            lines.append("# TYPE proxy_pool_affinity_pairs gauge")
            lines.append(f"proxy_pool_affinity_pairs {s.get('affinity', {}).get('affinity', 0)}")
            body = ("\n".join(lines) + "\n").encode()
            return http_response(200, "OK", [("Content-Type", "text/plain; charset=utf-8"),
                                             ("Connection", "close")], body)

        if path == "/report" and method == "POST":
            pid = int(payload.get("id", 0))
            p = pool.by_id.get(pid)
            if not p:
                return json_response({"error": "not found"}, 404)
            pool.report(p, bool(payload.get("ok")), float(payload.get("latency_ms", 0)))
            return json_response({"ok": True, "state": p.state, "score": round(p.score, 4)})

        if path == "/rhythm" and method == "POST":
            # 运行时调节律：宿主按目标站点容忍度改均值/速率，不用重启
            try:
                if "mu" in payload:
                    pool.rhythm.mu = max(0.0, float(payload["mu"]))
                if "sigma" in payload:
                    pool.rhythm.sigma = max(0.0, float(payload["sigma"]))
                if "per_key_qps" in payload:
                    pool.rhythm.per_key_qps = max(0.01, float(payload["per_key_qps"]))
                if "global_qps" in payload:
                    pool.rhythm.global_qps = max(0.01, float(payload["global_qps"]))
                    pool.rhythm._global.rate = pool.rhythm.global_qps
                if "affinity_ttl" in payload:
                    pool.affinity.affinity_ttl = max(0.0, float(payload["affinity_ttl"]))
                if "proxy_cooldown" in payload:
                    pool.affinity.cooldown = max(0.0, float(payload["proxy_cooldown"]))
            except (TypeError, ValueError):
                return json_response({"error": "invalid_value"}, 400)
            return json_response({"ok": True, "mu": pool.rhythm.mu,
                                  "sigma": pool.rhythm.sigma,
                                  "per_key_qps": pool.rhythm.per_key_qps,
                                  "global_qps": pool.rhythm.global_qps,
                                  "affinity_ttl": pool.affinity.affinity_ttl,
                                  "proxy_cooldown": pool.affinity.cooldown})

        if path == "/add" and method == "POST":
            raw = payload.get("proxies") or []
            entries = []
            for item in raw:
                if isinstance(item, str):
                    e = split_proxy_text(item)
                    if e:
                        entries.append(e)
                elif isinstance(item, dict) and item.get("host"):
                    entries.append({
                        "scheme": item.get("scheme", "http"),
                        "host": item["host"],
                        "port": int(item.get("port", 8080)),
                        "user": item.get("user", ""),
                        "password": item.get("password", ""),
                        "region": item.get("region", ""),
                        "source": item.get("source", "api"),
                    })
            if not self.token and any(e.get("user") or e.get("password") for e in entries):
                return json_response({"error": "api_token_required_for_credentialed_proxy"}, 403)
            added, dup = pool.add_many(entries)
            return json_response({"added": added, "duplicate": dup,
                                  "total": len(pool.proxies)})

        if path in ("/delete", "/rm") and method == "POST":
            ids = [int(x) for x in (payload.get("ids") or [])]
            return json_response({"deleted": pool.remove(ids)})

        if path.startswith("/proxy/"):
            rest = path[len("/proxy/"):]
            try:
                pid = int(rest)
            except ValueError:
                return json_response({"error": "bad id"}, 400)
            p = pool.by_id.get(pid)
            if not p:
                return json_response({"error": "not found"}, 404)
            if method == "DELETE":
                pool.remove([pid])
                return json_response({"deleted": 1})
            if method == "POST":
                if "enabled" in payload:
                    en = bool(payload["enabled"])
                    pool.store.set_enabled(pid, en)
                    p.enabled = en
                if payload.get("check"):
                    res = await self.app.checker.check_one(p)
                    return json_response({"ok": res[0], "latency_ms": round(res[1], 1),
                                          "reason": res[2], "state": p.state})
                return json_response(p.to_dict())
            return json_response(p.to_dict())

        if path == "/check" and method == "POST":
            scope = payload.get("scope", "all")
            deep = bool(payload.get("deep", False))
            if scope == "all":
                targets = [p for p in pool.proxies
                           if p.enabled and p.key not in pool.blacklist]
                res = await self.app.checker.check_many(targets)
                if deep:
                    res["deep"] = await self.app.checker.deep_check_many(targets)
            else:
                ids = [int(x) for x in (payload.get("ids") or [])]
                targets = [pool.by_id[i] for i in ids if i in pool.by_id]
                res = await self.app.checker.check_many(targets)
                if deep:
                    res["deep"] = await self.app.checker.deep_check_many(targets)
            return json_response(res)

        if path == "/audit" and method == "POST":
            # 五判据全量体检。ids 缺省对全体非黑名单代理跑一遍。
            ids = [int(x) for x in (payload.get("ids") or [])]
            if ids:
                targets = [pool.by_id[i] for i in ids if i in pool.by_id]
            else:
                targets = [p for p in pool.proxies
                           if p.enabled and p.key not in pool.blacklist]
            res = await self.app.checker.deep_check_many(targets)
            return json_response(res)

        if path == "/audit/detail":
            pid = int(query.get("id", ["0"])[0] or 0)
            p = pool.by_id.get(pid)
            if not p:
                return json_response({"error": "not found"}, 404)
            return json_response({"id": p.id, "grade": p.grade,
                                  "profile": p.profile, "audit": p.audit})

        if path == "/blacklist":
            if method == "DELETE":
                keys = payload.get("keys")
                freed = pool.clear_blacklist(keys if isinstance(keys, list) else None)
                return json_response({"freed": freed, "remaining": len(pool.blacklist)})
            return json_response({"keys": sorted(pool.blacklist),
                                  "count": len(pool.blacklist)})

        if path == "/hardening":
            return json_response({
                "rhythm": {"mu": pool.rhythm.mu, "sigma": pool.rhythm.sigma,
                           "per_key_qps": pool.rhythm.per_key_qps,
                           "global_qps": pool.rhythm.global_qps},
                "affinity": pool.affinity.stats(),
                "fingerprints": {pr.name: sum(1 for p in pool.proxies if p.profile == pr.name)
                                 for pr in pool.fingerprints.profiles},
                "gateway": {"rhythm_enabled": bool(self.app.gateway and
                                                   self.app.gateway.rhythm_on),
                            "shape_headers": bool(self.app.gateway and
                                                  self.app.gateway.shape_headers)},
            })

        if path in ("/reload", "/flush") and method == "POST":
            self.app.store.save_states(pool.proxies)
            return json_response({"ok": True, "flushed": len(pool.proxies)})

        return json_response({"error": "not found", "path": path}, 404)

    def _format(self, p: Proxy, fmt: str) -> bytes:
        if fmt == "text" or fmt == "plain":
            body = proxy_url(p, with_auth=False).encode()
            return http_response(200, "OK", [("Content-Type", "text/plain"),
                                             ("Connection", "close")], body)
        if fmt == "url":
            body = proxy_url(p, with_auth=True).encode()
            return http_response(200, "OK", [("Content-Type", "text/plain"),
                                             ("Connection", "close")], body)
        if fmt == "env":
            u = proxy_url(p, with_auth=True)
            body = (f"HTTP_PROXY={u}\nHTTPS_PROXY={u}\n"
                    f"http_proxy={u}\nhttps_proxy={u}\n").encode()
            return http_response(200, "OK", [("Content-Type", "text/plain"),
                                             ("Connection", "close")], body)
        if fmt == "curl":
            body = f"-x {proxy_url(p)}".encode()
            return http_response(200, "OK", [("Content-Type", "text/plain"),
                                             ("Connection", "close")], body)
        if fmt == "scrapy":
            profile = pool.fingerprints.by_name(p.profile)
            body = json.dumps({proxy_url(p, with_auth=False): shape_ua(profile)}).encode()
            return http_response(200, "OK", [("Content-Type", "application/json"),
                                             ("Connection", "close")], body)
        return json_response(p.to_dict(with_auth=True))

    def _html(self) -> bytes:
        s = self.app.pool.stats()
        gw = self.app.gateway
        gw_port = self.app.cfg["gateway"]["port"] if gw else "-"
        alive = "是" if s["alive"] else "否"
        html = f"""<!doctype html><meta charset=utf-8><title>proxypool {VERSION}</title>
<body style="font-family:ui-monospace,monospace;padding:24px;line-height:1.7">
<h2>proxypool {VERSION}</h2>
<table>
<tr><td>池总量</td><td>{s['total']}</td></tr>
<tr><td>可用(alive)</td><td>{s['alive']}</td></tr>
<tr><td>状态分布</td><td>{json.dumps(s['by_state'], ensure_ascii=False)}</td></tr>
<tr><td>延迟 P50 / P90</td><td>{s['latency_p50_ms']} ms / {s['latency_p90_ms']} ms</td></tr>
<tr><td>策略</td><td>{s['strategy']}</td></tr>
<tr><td>粘性会话</td><td>{s['sessions']}</td></tr>
</table>
<h3>接入</h3>
<pre>
网关直连:  export http_proxy=http://127.0.0.1:{gw_port} && export https_proxy=$http_proxy
取一个:    curl -s http://127.0.0.1:{self.port}/get?format=text
可用性:    {alive}（alive={s['alive']}）
</pre>
<p>端点: /get /get/&lt;session&gt; /all /stats /metrics /add /delete /check /health</p>
</body>"""
        return http_response(200, "OK", [("Content-Type", "text/html; charset=utf-8"),
                                         ("Connection", "close")], html.encode())


# ───────────────────────────── 应用装配 ─────────────────────────────

class App:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.store = Store(cfg["storage"]["db"],
                           bool(cfg["storage"].get("persist_credentials", False)))
        self.pool = ProxyPool(cfg, self.store)
        self.checker = Checker(cfg, self.pool)
        self.public_sources = PublicSourceManager(
            cfg.get("public_sources", []), self.pool, self.checker, split_proxy_text, log)
        self.direct_nodes = DirectNodeStore(cfg.get("direct_nodes", {}))
        self.gateway: Optional[Gateway] = None
        self.api = ApiServer(cfg, self)
        self.servers: list[asyncio.AbstractServer] = []
        self.started_at = time.time()
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()

    # —— 数据源（file / url，可周期刷新）——
    async def load_sources(self, include_public: bool = True) -> None:
        for src in self.cfg.get("sources") or []:
            try:
                await self._load_one_source(src)
            except Exception as e:
                log("warn", "source 加载失败 %r: %r", src, e)
        if include_public:
            await self.public_sources.refresh()

    async def _load_one_source(self, src: dict) -> None:
        typ = src.get("type", "file")
        text = ""
        if typ == "file":
            path = src["path"]
            if not os.path.isfile(path):
                log("debug", "source 文件不存在: %s", path)
                return
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        elif typ == "url":
            import urllib.request
            req = urllib.request.Request(src["url"], headers={"User-Agent": DEFAULT_UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                text = r.read().decode("utf-8", "replace")
            self.pool.dirty = True
        else:
            return
        entries = []
        for line in text.splitlines():
            e = split_proxy_text(line)
            if e:
                e["source"] = src.get("name", typ + ":" + str(src.get("path") or src.get("url")))
                entries.append(e)
        if entries:
            added, dup = self.pool.add_many(entries)
            log("info", "source %s: 新增 %d 条，重复 %d 条", src.get("name", typ), added, dup)

    # —— 后台任务 ——
    async def _flusher(self) -> None:
        interval = float(self.cfg["storage"]["flush_interval"])
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            if self.pool.dirty:
                try:
                    self.store.save_states(self.pool.proxies)
                    self.pool.dirty = False
                except Exception as e:
                    log("warn", "flush 失败: %r", e)
            self.pool.purge_sessions()

    async def _sweeper(self) -> None:
        c = self.cfg["checker"]
        if c["startup_sweep"] and self.pool.proxies:
            log("info", "启动体检：%d 条代理", len(self.pool.proxies))
            res = await self.checker.check_all()
            log("info", "启动体检完成：%s", res)
        if not c["enabled"] or float(c["interval"]) <= 0:
            return
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), float(c["interval"]))
                return
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                return
            res = await self.checker.check_all()
            log("info", "周期体检：%s | %s", res, self.pool.stats()["by_state"])

    # —— 启停 ——
    async def start(self) -> None:
        c = self.cfg
        if c["gateway"]["enabled"]:
            self.gateway = Gateway(c, self.pool, self.checker)
            srv = await asyncio.start_server(self.gateway.handle,
                                             c["gateway"]["host"],
                                             c["gateway"]["port"], limit=MAX_HEAD)
            self.servers.append(srv)
            log("info", "网关监听 http://%s:%s  （宿主程序把代理指到这里）",
                c["gateway"]["host"], c["gateway"]["port"])
        srv = await asyncio.start_server(self.api.handle, c["api"]["host"],
                                         c["api"]["port"], limit=MAX_HEAD)
        self.servers.append(srv)
        log("info", "API  监听 http://%s:%s  （/get /stats /add /check）",
            c["api"]["host"], c["api"]["port"])

        # Keep gateway/API responsive while public candidates undergo slow network checks.
        await self.load_sources(include_public=False)
        self._tasks.append(asyncio.create_task(self.public_sources.refresh()))
        self._tasks.append(asyncio.create_task(self._flusher()))
        self._tasks.append(asyncio.create_task(self._sweeper()))
        self._tasks.append(asyncio.create_task(self.public_sources.run(self._stop)))

    async def stop(self) -> None:
        self._stop.set()
        for s in self.servers:
            s.close()
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        try:
            self.store.save_states(self.pool.proxies)
        except Exception:
            pass
        self.store.close()
        log("info", "已停止")


# ───────────────────────────── 自测 ─────────────────────────────

async def _mock_origin(reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
    try:
        first, headers = await read_head(reader)
    except Exception:
        writer.close()
        return
    payload = json.dumps({
        "path": first,
        "headers": {k.lower(): v for k, v in headers},
        "origin": "mock-origin",
    }).encode()
    writer.write(http_response(200, "OK",
                               [("Content-Type", "application/json"),
                                ("Connection", "close")], payload))
    try:
        await writer.drain()
        writer.close()
    except Exception:
        pass


async def _mock_proxy(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
    """最小 HTTP 正向代理：只处理 absolute-form GET，转发后加标记头。"""
    try:
        first, headers = await read_head(reader)
    except Exception:
        writer.close()
        return
    parts = first.split()
    if len(parts) < 2 or parts[0].upper() == "CONNECT":
        writer.write(http_response(502, "Bad Gateway", [("Connection", "close")],
                                   b"mock proxy: CONNECT not supported"))
        try:
            await writer.drain()
            writer.close()
        except Exception:
            pass
        return
    u = urllib.parse.urlsplit(parts[1])
    if not u.hostname:
        writer.close()
        return
    try:
        r, w = await asyncio.open_connection(u.hostname, u.port or 80)
    except Exception:
        writer.write(http_response(502, "Bad Gateway", [("Connection", "close")],
                                   b"mock proxy: connect failed"))
        try:
            await writer.drain()
            writer.close()
        except Exception:
            pass
        return
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    lines = [f"GET {path} HTTP/1.1", f"Host: {u.netloc}", "X-Via-Mock-Proxy: 1"]
    for k, v in headers:
        if k.lower() in ("host", "proxy-connection", "proxy-authorization", "connection"):
            continue
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")
    w.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    try:
        await w.drain()
        while True:
            data = await r.read(CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    for c in (w, writer):
        try:
            c.close()
        except Exception:
            pass


async def selftest() -> int:
    import shutil
    import tempfile

    print("=" * 60)
    print(f"proxypool {VERSION} 自测")
    print("=" * 60)
    ok = True

    def check(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}{('  ' + extra) if extra else ''}")
        if not cond:
            ok = False

    # 自测数据库放当前目录（部分受限环境下新建子目录内无法建库）
    _here = os.path.dirname(os.path.abspath(__file__))
    tmpdir = _here
    _dbpath = os.path.join(_here, f".selftest-{os.getpid()}.db")
    origin_srv = await asyncio.start_server(_mock_origin, "127.0.0.1", 19001)
    proxy_srv = await asyncio.start_server(_mock_proxy, "127.0.0.1", 19002)
    check("mock origin 已启动 :19001", True)
    check("mock proxy 已启动 :19002", True)

    cfg = deep_merge(DEFAULT_CONFIG, {
        "api": {"port": 19011, "token": ""},
        "gateway": {"port": 19010, "enabled": True, "max_retry": 1},
        "checker": {"interval": 0, "startup_sweep": False, "timeout": 5.0,
                    "targets": ["http://127.0.0.1:19001/echo"], "expect_contains": "",
                    "content_check": False},
        "storage": {"db": _dbpath},
    })
    app = App(cfg)

    # 1. 入库
    added, dup = app.pool.add_many([
        {"scheme": "http", "host": "127.0.0.1", "port": 19002, "source": "selftest"},
        {"scheme": "http", "host": "127.0.0.1", "port": 19002, "source": "dup"},
        {"scheme": "http", "host": "127.0.0.1", "port": 19099, "source": "dead"},
    ])
    check("add_many 去重（2 新增 1 重复）", added == 2 and dup == 1, f"added={added} dup={dup}")

    # 2. 解析器
    e = split_proxy_text("socks5://u:p@1.2.3.4:1080")
    check("split_proxy_text 解析 socks5 带认证",
          e is not None and e["scheme"] == "socks5" and e["port"] == 1080
          and e["user"] == "u", str(e))
    e2 = split_proxy_text("1.2.3.4:8080")
    check("split_proxy_text 裸 host:port 补默认 http",
          e2 is not None and e2["scheme"] == "http" and e2["port"] == 8080, str(e2))

    # 3. 体检：好的应该 alive，坏的应该 probation/dead
    good = app.pool.proxies[0]
    bad = app.pool.proxies[1]
    okg, latg, r1 = await app.checker.check_one(good)
    check("健康代理体检通过", okg, f"{latg:.1f}ms {r1}")
    for _ in range(3):
        await app.checker.check_one(bad)
    check("坏代理判死", bad.state == "dead", f"state={bad.state} consec={bad.consec_fail}")

    # 4. 调度只出好的
    picked = [app.pool.pick() for _ in range(20)]
    check("pick 不返回死代理",
          all(p is not None and p.id == good.id for p in picked))

    # 5. 粘性会话
    s1 = app.pool.pick(session_key="user-42")
    s2 = app.pool.pick(session_key="user-42")
    check("粘性会话命中同一代理", s1 is not None and s1.id == s2.id)

    # 6. 网关：HTTP 明文转发 + 上游标记头
    gw = Gateway(cfg, app.pool, app.checker)
    app.gateway = gw
    gw_srv = await asyncio.start_server(gw.handle, "127.0.0.1", 19010)

    import urllib.request
    proxy_url_str = "http://127.0.0.1:19010"

    def fetch_via_gw() -> str:
        op = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url_str}))
        with op.open("http://127.0.0.1:19001/echo?a=1", timeout=10) as r:
            return r.read().decode()

    text = await asyncio.to_thread(fetch_via_gw)
    data = json.loads(text)
    check("网关转发 HTTP 成功", "path" in data and "mock-origin" in data.get("origin", ""))
    check("请求确实经过上游代理",
          data["headers"].get("x-via-mock-proxy") == "1",
          str(data["headers"].get("x-via-mock-proxy")))
    check("网关已剥离 Proxy-Authorization",
          "proxy-authorization" not in data["headers"])

    # 7. API 端点
    api_srv = await asyncio.start_server(app.api.handle, "127.0.0.1", 19011)

    def api_get(path: str) -> str:
        with urllib.request.urlopen(f"http://127.0.0.1:19011{path}", timeout=10) as r:
            return r.read().decode()

    stats = json.loads(await asyncio.to_thread(api_get, "/stats"))
    check("API /stats 返回池统计", stats.get("total") == 2 and stats.get("alive") == 1,
          json.dumps(stats["by_state"]))
    one = await asyncio.to_thread(api_get, "/get?format=text")
    check("API /get?format=text 返回 host:port", ":" in one.strip(), one.strip())
    env = await asyncio.to_thread(api_get, "/get?format=env")
    check("API /get?format=env 返回环境变量", "HTTP_PROXY=" in env)
    metrics = await asyncio.to_thread(api_get, "/metrics")
    check("API /metrics 返回 Prometheus 文本", "proxy_pool_alive" in metrics)

    # 8. 持久化
    app.store.save_states(app.pool.proxies)
    app.store.close()
    st2 = Store(cfg["storage"]["db"])
    loaded = st2.load_all()
    check("SQLite 持久化后状态保留",
          len(loaded) == 2 and any(x.state == "alive" for x in loaded),
          str([x.state for x in loaded]))
    st2.close()

    # 9. 全部坏掉时 pick 返回 None 或 direct_fallback
    good.state = "dead"
    good.dead_until = time.time() + 3600
    check("无可用代理时 pick 返回 None", app.pool.pick() is None)

    for s in (origin_srv, proxy_srv, gw_srv, api_srv):
        s.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(_dbpath + suffix)
        except OSError:
            pass
    print("=" * 60)
    print("自测结果:", "全部通过" if ok else "有失败项")
    print("=" * 60)
    return 0 if ok else 1


# ───────────────────────────── main ─────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    global _log_level
    ap = argparse.ArgumentParser(
        prog="poolsd", description=f"通用代理池守护 v{VERSION}")
    ap.add_argument("-c", "--config", default="pool.json", help="配置文件路径")
    ap.add_argument("--host", help="API 监听地址（覆盖配置）")
    ap.add_argument("--port", type=int, help="API 监听端口")
    ap.add_argument("--gateway-port", type=int, help="网关监听端口")
    ap.add_argument("--token", help="API 访问令牌")
    ap.add_argument("--db", help="SQLite 路径")
    ap.add_argument("--strategy", help="调度策略 weighted_random|round_robin|fastest|random")
    ap.add_argument("--log-level", default=None, help="debug|info|warn|error")
    ap.add_argument("--selftest", action="store_true", help="跑内置自测后退出")
    ap.add_argument("--once", action="store_true", help="只体检一轮后退出")
    ap.add_argument("--import", dest="import_file", metavar="FILE",
                    help="启动时把文件里的代理导入池")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args(argv)

    if args.version:
        print(f"proxypool {VERSION}")
        return 0
    if args.selftest:
        return asyncio.run(selftest())

    cfg = load_config(args.config)
    if args.host:
        cfg["api"]["host"] = args.host
    if args.port:
        cfg["api"]["port"] = args.port
    if args.gateway_port:
        cfg["gateway"]["port"] = args.gateway_port
    if args.token is not None:
        cfg["api"]["token"] = args.token
    if args.db:
        cfg["storage"]["db"] = args.db
    if args.strategy:
        cfg["pool"]["strategy"] = args.strategy
    if args.log_level:
        cfg["log_level"] = args.log_level
    _log_level = LOG_LEVELS.get(cfg.get("log_level", "info"), 20)

    async def run_once() -> int:
        app = App(cfg)
        if args.import_file and os.path.isfile(args.import_file):
            with open(args.import_file, "r", encoding="utf-8", errors="replace") as f:
                entries = [e for e in (split_proxy_text(l) for l in f) if e]
            added, dup = app.pool.add_many(entries)
            log("info", "导入 %d 条（重复 %d）", added, dup)
        await app.load_sources()
        res = await app.checker.check_all()
        log("info", "体检完成：%s", res)
        print(json.dumps({"check": res, "stats": app.pool.stats()},
                         ensure_ascii=False, indent=2))
        app.store.save_states(app.pool.proxies)
        app.store.close()
        return 0

    async def run_forever() -> int:
        app = App(cfg)
        if args.import_file and os.path.isfile(args.import_file):
            with open(args.import_file, "r", encoding="utf-8", errors="replace") as f:
                entries = [e for e in (split_proxy_text(l) for l in f) if e]
            added, dup = app.pool.add_many(entries)
            log("info", "导入 %d 条（重复 %d）", added, dup)
        await app.start()
        stop = asyncio.Event()

        def _on_signal() -> None:
            log("info", "收到停止信号")
            stop.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _on_signal)
            except (NotImplementedError, AttributeError, ValueError):
                pass
        try:
            await stop.wait()
        except asyncio.CancelledError:
            pass
        await app.stop()
        return 0

    try:
        if args.once:
            return asyncio.run(run_once())
        return asyncio.run(run_forever())
    except KeyboardInterrupt:
        log("info", "中断退出")
        return 0


if __name__ == "__main__":
    sys.exit(main())