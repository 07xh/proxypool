#!/usr/bin/env python3
"""Offline regression for distinct retry candidates, sticky session and SDK behavior."""
from __future__ import annotations

import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from poolsd import DEFAULT_CONFIG, ProxyPool, Store
from poolclient import NoProxyAvailable, ProxyPoolClient, request_with_rotation


class FakeClient:
    def __init__(self):
        self.calls = []
        self.releases = []
        self.pairs = [
            {"id": 11, "url": "http://192.0.2.11:8080"},
            {"id": 22, "url": "http://192.0.2.22:8080"},
        ]

    def get(self, session=None, exclude_ids=None):
        for p in self.pairs:
            if p["id"] not in (exclude_ids or set()):
                return p
        raise NoProxyAvailable("no more candidates")

    def report(self, pid, ok, latency_ms=0):
        self.calls.append((pid, ok))

    def invalidate_session(self, session, proxy_id):
        self.releases.append((session, proxy_id))


def verify():
    cfg = {k: dict(v) if isinstance(v, dict) else v
           for k, v in DEFAULT_CONFIG.items()}
    store = Store(":memory:")
    try:
        pool = ProxyPool(cfg, store)
        pool.add_many([
            {"scheme": "http", "host": "192.0.2.11", "port": 8080},
            {"scheme": "http", "host": "192.0.2.22", "port": 8080},
        ])
        for p in pool.proxies:
            p.state = "alive"
        sticky = pool.pick(session_key="run/one")
        assert pool.pick(session_key="run/one").id == sticky.id
        other = pool.pick(session_key="run/one", exclude_ids={sticky.id})
        assert other is not None and other.id != sticky.id
        assert not pool.invalidate_session("run/one", sticky.id)
        assert pool.invalidate_session("run/one", other.id)
        assert not pool.invalidate_session("run/one", other.id)
        assert pool.pick(exclude_ids={p.id for p in pool.proxies}) is None
        assert pool.stats()["alive"] == 2
        pool.proxies[0].enabled = False
        assert pool.stats()["alive"] == 1

        fake = FakeClient()
        class Response:
            def __init__(self, status_code):
                self.status_code = status_code
        seen = []
        def fetch(proxy, pid):
            seen.append(pid)
            return Response(503 if pid == 11 else 200)

        result = request_with_rotation(fetch, fake, session="demo", attempts=4,
                                       method="GET", backoff=0)
        assert result.status_code == 200
        assert seen == [11, 22]
        assert fake.releases == [("demo", 11)]
        assert fake.calls == [(11, False), (22, True)]

        # Unknown methods and writes are never replayed.
        for method in ("", "POST"):
            fake = FakeClient()
            seen = []
            result = request_with_rotation(fetch, fake, attempts=5,
                                           method=method, backoff=0)
            assert result.status_code == 503 and seen == [11]

        # A 429 must not cause a fresh proxy selection.
        fake = FakeClient()
        seen = []
        def rate_limited(proxy, pid):
            seen.append(pid)
            return Response(429)
        result = request_with_rotation(rate_limited, fake, attempts=5,
                                       method="GET", backoff=0)
        assert result.status_code == 429 and seen == [11]

        # Distinct IPs are not interchangeable with endpoint counts.
        meter_store = Store(":memory:")
        try:
            meter = ProxyPool(cfg, meter_store)
            meter.add_many([
                {"scheme": "http", "host": "1.1.1.1", "port": 8080},
                {"scheme": "socks5", "host": "1.1.1.1", "port": 1080},
                {"scheme": "http", "host": "8.8.8.8", "port": 3128},
                {"scheme": "http", "host": "192.0.2.55", "port": 8080},
                {"scheme": "http", "host": "proxy.example", "port": 8080},
            ])
            for item in meter.proxies:
                item.state = "alive"
                item.last_ok = time.time()
            measured = meter.stats()
            assert measured["total"] == 5, measured
            assert measured["alive"] == 5, measured
            assert measured["unique_public_ipv4_total"] == 2, measured
            assert measured["unique_public_ipv4_alive"] == 2, measured
            assert measured["unique_public_ipv4_verified_5m"] == 2, measured
            meter.proxies[2].enabled = False
            meter.proxies[0].last_ok = time.time() - 400
            meter.proxies[1].last_ok = time.time() - 400
            measured = meter.stats()
            assert measured["unique_public_ipv4_total"] == 2, measured
            assert measured["unique_public_ipv4_alive"] == 1, measured
            assert measured["unique_public_ipv4_verified_5m"] == 0, measured
        finally:
            meter_store.close()

        client = ProxyPoolClient()
        calls = []
        def fake_api(path, data=None):
            calls.append((path, data))
            if path == "/stats":
                return {"unique_public_ipv4_alive": 3,
                        "unique_public_ipv4_verified_5m": 2}
            return {"sources": [{"name": "test-feed", "available_now": 1}]}
        client._req = fake_api
        assert client.public_ipv4_count() == 2
        assert client.public_ipv4_count(recent_only=False) == 3
        assert client.source_status()[0]["name"] == "test-feed"
        client.refresh_sources("test-feed")
        assert calls[-1] == ("/sources/refresh", {"name": "test-feed"})
        print("rotation/session/IP inventory regression: OK")
    finally:
        store.close()


if __name__ == "__main__":
    verify()
