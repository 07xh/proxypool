#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Optional public proxy feeds: bounded HTTPS imports and health-gated activation.

No dependencies beyond Python's standard library. Only explicitly configured,
public GitHub raw-text feeds are accepted. Never send account traffic through
untrusted public proxies.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
import urllib.parse
import urllib.request
from typing import Any, Callable

MAX_DOWNLOAD = 1024 * 1024
ALLOWED_HOSTS = {"raw.githubusercontent.com"}
SUPPORTED = {"http", "socks5"}


def validate_url(url: str) -> None:
    p = urllib.parse.urlsplit(url)
    if (p.scheme != "https" or p.hostname not in ALLOWED_HOSTS or
            p.username or p.password or p.query or p.fragment or not p.path.endswith(".txt")):
        raise ValueError("public feed must be a HTTPS raw.githubusercontent.com .txt URL")


class _StrictRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_feed(url: str) -> str:
    """Fetch a small, verified-TLS source without following off-host redirects."""
    validate_url(url)
    opener = urllib.request.build_opener(_StrictRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": "ProxyPool-public-sources/1.0"})
    with opener.open(req, timeout=12) as response:
        validate_url(response.geturl())
        raw = response.read(MAX_DOWNLOAD + 1)
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("public feed too large")
    return raw.decode("utf-8", "replace")


def parse_public(text: str, scheme: str, limit: int,
                 parse_line: Callable[[str], dict | None],
                 name: str) -> list[dict]:
    """Accept only globally routable IPv4, no credentials, no unsupported schemes."""
    if scheme not in SUPPORTED:
        raise ValueError("supported public schemes: http, socks5")
    out: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "@" in line:
            continue
        if "://" in line:
            try:
                explicit_scheme = urllib.parse.urlsplit(line).scheme.lower()
            except ValueError:
                continue
            if explicit_scheme != scheme:
                continue
        else:
            line = scheme + "://" + line
        entry = parse_line(line)
        if not entry or entry["scheme"] != scheme:
            continue
        try:
            addr = ipaddress.IPv4Address(entry["host"])
            port = int(entry["port"])
        except (ipaddress.AddressValueError, ValueError, TypeError):
            continue
        if not addr.is_global or not 1 <= port <= 65535:
            continue
        key = (scheme, str(addr), port)
        if key in seen:
            continue
        seen.add(key)
        entry["host"] = str(addr)
        entry["source"] = "public:" + name
        out.append(entry)
        if len(out) >= limit:
            break
    return out


class PublicSourceManager:
    """Refreshes opted-in feeds and checks candidates BEFORE enabling new proxies."""

    def __init__(self, configs: list[dict], pool: Any, checker: Any,
                 parse_line: Callable[[str], dict | None],
                 logger: Callable[..., None], fetch: Callable[[str], str] = download_feed):
        self.pool = pool
        self.checker = checker
        self.parse_line = parse_line
        self.log = logger
        self.fetch = fetch
        self.lock = asyncio.Lock()
        self.sources: dict[str, dict] = {}
        self.states: dict[str, dict] = {}
        for index, source in enumerate(configs or []):
            name = str(source.get("name") or f"feed-{index + 1}")
            if name in self.sources or not name.replace("-", "").replace("_", "").isalnum():
                raise ValueError("invalid or duplicate public source name")
            scheme = str(source.get("scheme") or "http").lower()
            if scheme not in SUPPORTED:
                raise ValueError("unsupported public source scheme: " + scheme)
            url = str(source.get("url") or "")
            validate_url(url)
            cfg = {
                "name": name, "url": url, "scheme": scheme,
                "enabled": bool(source.get("enabled", False)),
                "interval": max(300, min(86400, int(source.get("interval", 1800)))),
                "max_entries": max(1, min(150, int(source.get("max_entries", 80)))),
            }
            self.sources[name] = cfg
            self.states[name] = {
                "name": name, "url": url, "scheme": scheme,
                "enabled": cfg["enabled"], "next_refresh_ts": 0,
                "last_refresh_ts": 0, "last_success_ts": 0,
                "listed": 0, "added": 0, "duplicate": 0,
                "checked": 0, "alive_new": 0, "error": None,
            }
        # Persisted results from earlier sessions must be revalidated at startup.
        for proxy in self.pool.proxies:
            if proxy.source.startswith("public:"):
                proxy.enabled = False
                self.pool.store.set_enabled(proxy.id, False)

    def status(self) -> dict:
        rows = []
        for name, state in self.states.items():
            row = dict(state)
            members = [p for p in self.pool.proxies if p.source == "public:" + name]
            row["in_pool"] = len(members)
            row["available_now"] = sum(
                1 for p in members if p.enabled and p.state == "alive" and p.dead_until <= time.time())
            row["quarantined"] = sum(1 for p in members if not p.enabled)
            rows.append(row)
        return {"sources": rows}

    async def refresh(self, name: str | None = None, due_only: bool = False) -> dict:
        if name is not None and name not in self.sources:
            return {"error": "unknown_source", "name": name}
        async with self.lock:
            for source_name, cfg in self.sources.items():
                if name is not None and name != source_name:
                    continue
                state = self.states[source_name]
                if not cfg["enabled"]:
                    continue
                now = time.time()
                if due_only and state["next_refresh_ts"] > now:
                    continue
                state["last_refresh_ts"] = int(now)
                state["error"] = None
                try:
                    raw = await asyncio.to_thread(self.fetch, cfg["url"])
                    entries = parse_public(raw, cfg["scheme"], cfg["max_entries"],
                                           self.parse_line, source_name)
                    if not entries:
                        raise ValueError("no valid globally routable IPv4 proxies")
                    before = {p.key for p in self.pool.proxies}
                    added, duplicate = self.pool.add_many(entries)
                    just_added_keys = {
                        f'{e["scheme"]}://{e["host"]}:{e["port"]}'
                        for e in entries if f'{e["scheme"]}://{e["host"]}:{e["port"]}' not in before
                    }
                    for p in self.pool.proxies:
                        if p.key in just_added_keys:
                            p.enabled = False
                            self.pool.store.set_enabled(p.id, False)
                    keys = {f'{e["scheme"]}://{e["host"]}:{e["port"]}' for e in entries}
                    pending = [p for p in self.pool.proxies
                               if p.key in keys and p.source == "public:" + source_name
                               and not p.enabled]
                    gate = asyncio.Semaphore(8)

                    async def verify_one(p: Any) -> bool:
                        try:
                            async with gate:
                                ok, _, _ = await self.checker.check_one(p)
                            if ok:
                                self.pool.store.set_enabled(p.id, True)
                                p.enabled = True
                                self.pool.dirty = True
                            return bool(ok)
                        except Exception as exc:
                            self.log("warn", "public candidate check error: %s", type(exc).__name__)
                            return False

                    outcomes = await asyncio.gather(*(verify_one(p) for p in pending))
                    state.update({
                        "listed": len(entries), "added": added,
                        "duplicate": duplicate, "checked": len(pending),
                        "alive_new": sum(outcomes), "last_success_ts": int(time.time()),
                    })
                    self.log("info", "public source %s: listed=%d added=%d verified=%d/%d",
                             source_name, len(entries), added, sum(outcomes), len(pending))
                except Exception as exc:
                    state["error"] = f"{type(exc).__name__}: {exc}"
                    self.log("warn", "public source %s failed: %s",
                             source_name, type(exc).__name__)
                finally:
                    state["next_refresh_ts"] = int(time.time() + cfg["interval"])
            return self.status()

    async def run(self, stop: asyncio.Event) -> None:
        if not any(cfg["enabled"] for cfg in self.sources.values()):
            return
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 30)
                break
            except asyncio.TimeoutError:
                await self.refresh(due_only=True)
