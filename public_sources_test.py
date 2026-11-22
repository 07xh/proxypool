#!/usr/bin/env python3
"""Offline tests for public feed parsing, deduplication, quarantine and refresh."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from poolsd import DEFAULT_CONFIG, ProxyPool, Store, split_proxy_text
from public_sources import PublicSourceManager, parse_public, validate_url

FEED = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"


class FakeChecker:
    def __init__(self):
        self.calls = []

    async def check_one(self, proxy):
        self.calls.append(proxy.key)
        good = proxy.host == "1.1.1.1"
        proxy.state = "alive" if good else "dead"
        return good, 10.0, "offline"


def run() -> None:
    try:
        validate_url("http://example.org/list.txt")
        raise AssertionError("insecure URL accepted")
    except ValueError:
        pass
    parsed = parse_public(
        "1.1.1.1:8080\n1.1.1.1:8080\n127.0.0.1:80\n"
        "192.168.1.1:1080\nhttp://8.8.8.8:3128\n"
        "socks4://1.1.1.1:1080\nhttp://[bad-address\nuser:pass@8.8.8.8:80\n",
        "http", 10, split_proxy_text, "test")
    assert len(parsed) == 2, parsed
    assert all(x["source"] == "public:test" for x in parsed)

    cfg = {k: dict(v) if isinstance(v, dict) else v for k, v in DEFAULT_CONFIG.items()}
    store = Store(":memory:")
    pool = ProxyPool(cfg, store)
    checker = FakeChecker()
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return "1.1.1.1:8080\n8.8.8.8:3128\n127.0.0.1:1234\n"

    def mkmanager():
        return PublicSourceManager([
            {"name": "test", "url": FEED, "scheme": "http",
             "enabled": True, "interval": 300, "max_entries": 10}
        ], pool, checker, split_proxy_text, lambda *a: None, fetch=fake_fetch)

    async def checks():
        manager = mkmanager()
        result = await manager.refresh()
        state = result["sources"][0]
        assert state["added"] == 2 and state["checked"] == 2, state
        assert state["alive_new"] == 1
        assert pool.by_id[1].enabled and not pool.by_id[2].enabled
        again = await manager.refresh()
        assert again["sources"][0]["added"] == 0
        assert again["sources"][0]["checked"] == 1
        assert len(pool.proxies) == 2
        due = await manager.refresh(due_only=True)
        assert len(calls) == 2
        assert due["sources"][0]["next_refresh_ts"] > 0
        store.save_states(pool.proxies)
        # On a new process, previously accepted public proxies require re-checking.
        restarted = mkmanager()
        assert not pool.by_id[1].enabled
        await restarted.refresh()
        assert pool.by_id[1].enabled
        assert (await restarted.refresh(name="missing"))["error"] == "unknown_source"

    try:
        asyncio.run(checks())
        print("public_sources offline tests: OK")
    finally:
        store.close()


if __name__ == "__main__":
    run()
