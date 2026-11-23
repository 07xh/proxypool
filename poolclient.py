#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poolclient.py — 代理池的三套接入法（按宿主程序选一条，不用混用）

用法一 · 网关模式（最省事，宿主什么都不用改）
    # 进程级：整个程序的所有出网流量自动轮换
    set HTTP_PROXY=http://127.0.0.1:18080
    set HTTPS_PROXY=http://127.0.0.1:18080
    -> 之后 curl / requests / scrapy / selenium / Chrome 全部走池子

用法二 · 取用模式（宿主自己控制每次请求换不换线）
    from poolclient import ProxyPoolClient
    pc = ProxyPoolClient("http://127.0.0.1:18081")
    url = pc.get_url()                  # 随机一轮
    url = pc.get_url(session="job-1")   # 同一任务粘住同一条线

用法三 · 回调上报（让池子知道你的真实成败，比体检更准）
    pc.report(proxy_id, ok=True, latency_ms=120)
"""
from __future__ import annotations

import base64
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

DEFAULT_API = "http://127.0.0.1:18081"
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


class NoProxyAvailable(RuntimeError):
    """池子里一条可用代理都没有。宿主可据此降级为直连或暂停任务。"""


class NoDirectNodeAvailable(RuntimeError):
    """指定目标没有新鲜的直连 TLS 节点。这不是代理池错误。"""


class ProxyPoolClient:
    def __init__(self, api_base: str = DEFAULT_API, token: str = "",
                 timeout: float = 5.0) -> None:
        self.api = api_base.rstrip("/")
        self.token = token
        self.timeout = timeout
        # Control requests must never loop through the proxy gateway itself.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # ── 底层 HTTP ──
    def _req(self, path: str, data: Optional[dict] = None,
             method: Optional[str] = None) -> Any:
        url = self.api + path
        body = None
        headers = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method or ("POST" if body else "GET"))
        with self._opener.open(req, timeout=self.timeout) as r:
            raw = r.read().decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    # ── 取代理 ──
    def get(self, session: Optional[str] = None,
            strategy: Optional[str] = None,
            exclude_ids: Optional[set[int]] = None,
            host: Optional[str] = None,
            affinity: bool = True) -> dict:
        """取一条代理。

        host 非空时启用「目标域亲和 + 单出口冷却」：同一站点在窗口内复用同一
        出口，冷却窗口内不重复压同一出口。affinity=False 只保留冷却，
        适合并发抓取（并发时绑亲和会把整个站点压到一条线上）。
        """
        q = {}
        if strategy:
            q["strategy"] = strategy
        if exclude_ids:
            q["exclude"] = ",".join(str(pid) for pid in sorted(exclude_ids))
        if host:
            q["host"] = host
        path = "/get"
        if session:
            path = "/get/" + urllib.parse.quote(session, safe="")
            if not affinity:
                q["affinity"] = "0"
        if q:
            path += "?" + urllib.parse.urlencode(q)
        try:
            res = self._req(path)
        except urllib.error.HTTPError as e:
            if e.code == 503:
                raise NoProxyAvailable("池子当前无可用代理") from None
            raise
        if isinstance(res, dict) and res.get("error"):
            raise NoProxyAvailable(res["error"])
        return res

    def get_url(self, session: Optional[str] = None,
                strategy: Optional[str] = None,
                host: Optional[str] = None) -> str:
        return self.get(session=session, strategy=strategy, host=host)["url"]

    def get_requests_proxies(self, session: Optional[str] = None,
                             host: Optional[str] = None) -> dict:
        """直接喂给 requests 的 proxies= 参数。host 传目标域名即开始做亲和。"""
        p = self.get(session=session, host=host)
        u = p["url"]
        return {"http": u, "https": u}

    def get_headers(self, session: Optional[str] = None,
                    host: Optional[str] = None) -> dict:
        """取该出口对应画像的头（UA / Accept-Language / Client Hints）。

        宿主自己发请求时用这一组头，才能和出口的 TLS 指纹对上；
        出口是 Chrome 却自己发 curl UA，等于把画像白做了。
        """
        p = self.get(session=session, host=host)
        profile = p.get("profile") or ""
        from poolopt import FingerprintBook
        book = FingerprintBook()
        prof = book.by_name(profile) or book.profiles[0]
        headers = {"User-Agent": prof.ua, "Accept-Language": prof.lang,
                   "Accept-Encoding": "gzip, deflate, br"}
        headers.update(prof.extra)
        return {"proxy": p, "headers": headers}

    def get_curl_arg(self) -> str:
        return self._req("/get?format=curl").strip()

    # ── 直连 TLS 节点（与代理取用完全隔离） ──
    def direct_stats(self) -> dict:
        return self._req("/direct/stats")

    def direct_list(self, host: Optional[str] = None) -> list[dict]:
        path = "/direct/all"
        if host:
            path += "?" + urllib.parse.urlencode({"host": host})
        return self._req(path).get("nodes", [])

    def direct_get(self, host: str) -> dict:
        """Return IP/port/SNI metadata, not an HTTP or SOCKS proxy URL."""
        path = "/direct/get?" + urllib.parse.urlencode({"host": host})
        try:
            return self._req(path)
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 503):
                raise NoDirectNodeAvailable(f"direct TLS node unavailable for {host}") from None
            raise

    def direct_reload(self) -> dict:
        return self._req("/direct/reload", {})

    # ── 上报 ──
    def report(self, proxy_id: int, ok: bool, latency_ms: float = 0.0) -> dict:
        return self._req("/report", {"id": proxy_id, "ok": ok,
                                     "latency_ms": latency_ms})

    def invalidate_session(self, session: str, proxy_id: Optional[int] = None) -> dict:
        """Unstick a failed session, without invalidating a newer assignment."""
        return self._req("/sessions/invalidate", {
            "session": session, "proxy_id": proxy_id})

    # ── 池管理 ──
    def stats(self) -> dict:
        return self._req("/stats")

    def alive(self) -> list:
        return self._req("/all?alive=1")["proxies"]

    def source_status(self) -> list[dict]:
        """Read public feed statistics; no proxy traffic or refresh triggered."""
        return self._req("/sources").get("sources", [])

    def refresh_sources(self, name: Optional[str] = None) -> dict:
        """Refresh configured public proxy feeds explicitly."""
        payload = {} if name is None else {"name": name}
        return self._req("/sources/refresh", payload)

    def public_ipv4_count(self, recent_only: bool = True) -> int:
        """Distinct globally routable IPv4 count, not proxy endpoint count.

        recent_only counts healthy addresses verified in the past five minutes.
        Hostname-only proxies cannot be resolved to unique IPs from pool data.
        """
        stats = self.stats()
        key = ("unique_public_ipv4_verified_5m" if recent_only
               else "unique_public_ipv4_alive")
        return int(stats.get(key, 0))

    def add(self, proxies: list) -> dict:
        return self._req("/add", {"proxies": proxies})

    def delete(self, ids: list) -> dict:
        return self._req("/delete", {"ids": ids})

    def check(self) -> dict:
        return self._req("/check", {"scope": "all"})

    def audit(self, ids: Optional[list] = None, deep: bool = True) -> dict:
        """五判据全量体检：透明性 / 注入 / 篡改 / 一致性 / 端口面。"""
        payload = {"ids": ids} if ids else {}
        return self._req("/audit", payload)

    def audit_detail(self, proxy_id: int) -> dict:
        return self._req(f"/audit/detail?id={int(proxy_id)}")

    def blacklist(self) -> dict:
        return self._req("/blacklist")

    def clear_blacklist(self, keys: Optional[list] = None) -> dict:
        return self._req("/blacklist", {"keys": keys}, method="DELETE")

    def hardening(self) -> dict:
        return self._req("/hardening")

    def set_rhythm(self, **kwargs) -> dict:
        """运行时调节律：mu / sigma / per_key_qps / global_qps / affinity_ttl / proxy_cooldown。"""
        return self._req("/rhythm", kwargs)

    def wait_ready(self, min_alive: int = 1, timeout: float = 60.0,
                   poll: float = 1.0) -> dict:
        """等池子热起来，给容器编排 / 宿主启动用。"""
        deadline = time.time() + timeout
        last: dict = {}
        while time.time() < deadline:
            try:
                last = self.stats()
                if last.get("alive", 0) >= min_alive:
                    return last
            except Exception:
                pass
            time.sleep(poll)
        return last


# ───────────────────────── 网关模式线程封装 ─────────────────────────

class GatewaySession:
    """
    把一个进程的出网流量整体接管到本地网关。
    只该在「单线程独占进程」或「确定宿主全程走池」时用；
    多线程正在并发请求时切换环境变量会污染中途连接。
    """

    KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
            "NO_PROXY", "no_proxy", "PROXYPOOL_GATEWAY_AUTH")

    def __init__(self, gateway: str = "http://127.0.0.1:18080",
                 auth: str = "") -> None:
        self.gateway = gateway
        self.auth = auth
        self._backup: dict[str, Optional[str]] = {}

    def __enter__(self) -> "GatewaySession":
        import os
        for k in self.KEYS:
            self._backup[k] = os.environ.get(k)
        for k in self.KEYS[:4]:
            os.environ[k] = self.gateway
        if self.auth:
            os.environ["PROXYPOOL_GATEWAY_AUTH"] = self.auth
        # 绕开网关自身，避免自我回环
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        os.environ["no_proxy"] = "127.0.0.1,localhost"
        return self

    def __exit__(self, *exc: Any) -> None:
        import os
        for k, v in self._backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ───────────────────────── 失败换线重试器 ─────────────────────────

def request_with_rotation(fn, client: ProxyPoolClient, session: Optional[str] = None,
                          attempts: int = 3, backoff: float = 0.5,
                          retry_status: tuple = (500, 502, 503, 504),
                          method: str = "",
                          host: Optional[str] = None):
    """Retry only explicitly declared safe read requests on distinct upstreams.

    Pass method="GET" (or HEAD/OPTIONS) to enable retries. Unknown and write
    methods are never retried. HTTP 429 is returned unchanged; respect the
    target service's rate limits rather than attempting another IP.
    """
    retryable = method.upper() in ("GET", "HEAD", "OPTIONS")
    rounds = max(1, attempts) if retryable else 1
    last_exc: Optional[BaseException] = None
    last_result = None
    tried: set[int] = set()
    for i in range(rounds):
        try:
            p = client.get(session=session, exclude_ids=tried, host=host)
        except NoProxyAvailable:
            if last_result is not None:
                return last_result
            if last_exc is not None:
                raise last_exc
            raise
        pid = p["id"]
        tried.add(pid)
        url = p["url"]
        t0 = time.monotonic()
        try:
            res = fn(url, pid)
        except Exception as e:
            last_exc = e
            client.report(pid, False, 0.0)
            if session and i < rounds - 1:
                client.invalidate_session(session, pid)
            if i < rounds - 1 and backoff > 0:
                time.sleep(backoff * (2 ** i) + random.uniform(0, 0.2))
            continue
        lat = (time.monotonic() - t0) * 1000
        status = getattr(res, "status_code", None)
        if status in retry_status and retryable:
            last_result = res
            client.report(pid, False, lat)
            if i < rounds - 1:
                if session:
                    client.invalidate_session(session, pid)
                if backoff > 0:
                    time.sleep(backoff * (2 ** i) + random.uniform(0, 0.2))
                continue
            return res
        client.report(pid, status is None or status < 500, lat)
        return res
    if last_result is not None:
        return last_result
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("No usable upstream proxy was available")


if __name__ == "__main__":
    pc = ProxyPoolClient()
    try:
        st = pc.stats()
        print(f"池总量={st['total']} 可用={st['alive']} 分布={st['by_state']}")
        print("取一条:", pc.get_url(session="demo"))
    except NoProxyAvailable as e:
        print("无可用代理:", e)
    except urllib.error.URLError as e:
        print("代理池 API 没在跑:", e.reason)