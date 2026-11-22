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
            exclude_ids: Optional[set[int]] = None) -> dict:
        q = {}
        if strategy:
            q["strategy"] = strategy
        if exclude_ids:
            q["exclude"] = ",".join(str(pid) for pid in sorted(exclude_ids))
        path = "/get"
        if session:
            path = "/get/" + urllib.parse.quote(session, safe="")
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
                strategy: Optional[str] = None) -> str:
        return self.get(session=session, strategy=strategy)["url"]

    def get_requests_proxies(self, session: Optional[str] = None) -> dict:
        """直接喂给 requests 的 proxies= 参数。"""
        p = self.get(session=session)
        u = p["url"]
        return {"http": u, "https": u}

    def get_curl_arg(self) -> str:
        return self._req("/get?format=curl").strip()

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

    def add(self, proxies: list) -> dict:
        return self._req("/add", {"proxies": proxies})

    def delete(self, ids: list) -> dict:
        return self._req("/delete", {"ids": ids})

    def check(self) -> dict:
        return self._req("/check", {"scope": "all"})

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
                          method: str = ""):
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
            p = client.get(session=session, exclude_ids=tried)
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