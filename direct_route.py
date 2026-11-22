#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Opt-in direct TLS endpoint routing, separate from HTTP/SOCKS proxy pool.

Uses the single DirectNodeStore for imported observations; runtime status is
ephemeral. CONNECT uses raw TCP. The *client* supplies TLS SNI and verifies
the certificate. Explicit diagnostics perform HTTPS with system CA checking.
"""
from __future__ import annotations
import asyncio
import re
import ssl
import time
from typing import Any
from direct_nodes import DirectNode, DirectNodeStore, _valid_host


class DirectRouteManager:
    def __init__(self, store: DirectNodeStore, config: dict[str, Any]):
        self.store = store
        self.enabled = bool(config.get("route_enabled", False))
        self.max_retry = min(4, max(0, int(config.get("route_retry", 2))))
        self.timeout = min(20., max(1., float(config.get("route_timeout", 6))))
        self.max_fail = min(10, max(1, int(config.get("max_fail", 3))))
        self.cooldown = min(3600., max(5., float(config.get("cooldown_s", 120))))
        self.health: dict[tuple[str, int, str], dict[str, Any]] = {}
        self.counters = {"tcp_ok": 0, "tcp_fail": 0, "https_ok": 0,
                         "https_fail": 0, "fallback": 0}
        self._verify_lock = asyncio.Lock()

    @staticmethod
    def key(node: DirectNode) -> tuple[str, int, str]:
        return (node.ip, node.port, node.sni)

    def _state(self, node: DirectNode) -> dict[str, Any]:
        return self.health.setdefault(self.key(node), {
            "state": "untested", "last_test_ts": 0, "last_ok_ts": 0,
            "consecutive_failures": 0, "dead_until": 0, "tcp_connected": False,
            "https_verified": False, "last_error": None, "latency_ms": None})

    def matches(self, host: str, port: int = 443) -> bool:
        if not self.enabled or port != 443 or not self.store.is_fresh():
            return False
        try:
            host = _valid_host(host)
        except ValueError:
            return False
        return host in self.store.allowed_hosts and any(
            n.sni == host and n.port == 443 for n in self.store.nodes)

    def pick(self, host: str, excluded: set[tuple[str, int, str]]):
        if not self.matches(host):
            return None
        now = time.time()
        choices = [n for n in self.store.nodes
                   if n.sni == host.lower() and n.port == 443
                   and self.key(n) not in excluded
                   and self._state(n)["dead_until"] <= now]
        choices.sort(key=lambda n: (
            not self._state(n)["https_verified"],
            self._state(n)["latency_ms"] or n.latency_ms or 1e9, n.ip))
        return choices[0] if choices else None

    def record(self, node: DirectNode, ok: bool, latency_ms: float = 0.,
               *, verified_https: bool = False, error: str | None = None) -> None:
        state = self._state(node)
        now = time.time()
        state["last_test_ts"] = int(now)
        if ok:
            state["consecutive_failures"] = 0
            state["dead_until"] = 0
            state["last_ok_ts"] = int(now)
            state["tcp_connected"] = True
            state["https_verified"] = state["https_verified"] or verified_https
            state["state"] = "https_verified" if state["https_verified"] else "tcp_connected"
            state["last_error"] = None
            if latency_ms > 0:
                old = state["latency_ms"]
                state["latency_ms"] = round(latency_ms if old is None else
                                            0.7 * old + 0.3 * latency_ms, 1)
            self.counters["https_ok" if verified_https else "tcp_ok"] += 1
        else:
            state["consecutive_failures"] += 1
            state["https_verified"] = False
            state["tcp_connected"] = False
            state["last_error"] = error or "connection_failed"
            self.counters["https_fail" if verified_https else "tcp_fail"] += 1
            if state["consecutive_failures"] >= self.max_fail:
                state["dead_until"] = now + self.cooldown
                state["state"] = "cooldown"
            else:
                state["state"] = "failed"

    def annotate(self, node: DirectNode) -> dict[str, Any]:
        result = node.as_dict()
        state = self.health.get(self.key(node), {})
        result.update({
            "route_state": state.get("state", "untested"),
            "route_latency_ms": state.get("latency_ms"),
            "https_verified": state.get("https_verified", False),
            "dead_until": int(state.get("dead_until", 0)),
            "last_error": state.get("last_error")})
        return result

    def stats(self) -> dict[str, Any]:
        now = time.time()
        keys = {self.key(n) for n in self.store.nodes}
        cooling = sum(1 for k in keys if
                      self.health.get(k, {}).get("dead_until", 0) > now)
        https_ok = sum(1 for k in keys if
                       self.health.get(k, {}).get("https_verified", False))
        return {"route_enabled": self.enabled,
                "eligible": len(keys) - cooling if self.store.is_fresh() else 0,
                "cooldown": cooling, "https_verified": https_ok,
                "route_counters": dict(self.counters),
                "routing_requires_tls_client": True}

    def prune(self) -> None:
        keys = {self.key(n) for n in self.store.nodes}
        self.health = {k: v for k, v in self.health.items() if k in keys}

    async def connect(self, node: DirectNode):
        """Raw TCP; the CONNECT client's TLS stream must not be nested in TLS."""
        return await asyncio.wait_for(
            asyncio.open_connection(node.ip, node.port), timeout=self.timeout)

    async def probe_one(self, node: DirectNode) -> dict[str, Any]:
        """Explicit HTTPS HEAD probe. Verify node certificate against SNI."""
        if node.sni not in self.store.allowed_hosts:
            raise ValueError("host_not_allowed")
        writer = None
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                node.ip, node.port, ssl=ssl.create_default_context(),
                server_hostname=node.sni, limit=16384), timeout=self.timeout)
            query = (f"HEAD / HTTP/1.1\r\nHost: {node.sni}\r\n"
                     "User-Agent: ProxyPool-NodeCheck/1.0\r\n"
                     "Connection: close\r\n\r\n").encode("ascii")
            writer.write(query)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)
            statusline = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            m = re.match(rb"HTTP/1\.[01] ([0-9]{3})\b", statusline)
            status = int(m.group(1)) if m else 0
            ok = 200 <= status < 400
            delay = (time.monotonic() - start) * 1000
            self.record(node, ok, delay, verified_https=True,
                        error=None if ok else f"http_{status}")
            return {"ip": node.ip, "sni": node.sni, "ok": ok,
                    "status": status, "tls_verified": True,
                    "latency_ms": round(delay, 1)}
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError) as exc:
            self.record(node, False, verified_https=True, error=type(exc).__name__)
            return {"ip": node.ip, "sni": node.sni, "ok": False,
                    "tls_verified": False, "error": type(exc).__name__}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except (OSError, asyncio.TimeoutError, ssl.SSLError):
                    pass

    async def verify(self, *, host: str | None = None, limit: int = 6) -> dict[str, Any]:
        """Bounded, manual diagnostic; never probes when the daemon starts."""
        if host is not None:
            host = _valid_host(host)
            if host not in self.store.allowed_hosts:
                raise ValueError("host_not_allowed")
        if not 1 <= limit <= 12:
            raise ValueError("limit must be 1..12")
        if not self.store.is_fresh():
            return {"checked": 0, "ok": 0, "error": "node_list_missing_or_stale"}
        selected = [n for n in self.store.nodes if host is None or n.sni == host][:limit]
        async with self._verify_lock:
            results = []
            for node in selected:
                results.append(await self.probe_one(node))
        return {"checked": len(results),
                "ok": sum(bool(item["ok"]) for item in results),
                "results": results}
