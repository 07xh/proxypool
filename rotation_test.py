#!/usr/bin/env python3
"""Offline regression for distinct retry candidates, sticky session and SDK behavior."""
from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from poolsd import DEFAULT_CONFIG, ProxyPool, Store
from poolclient import NoProxyAvailable, request_with_rotation


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
        print("rotation/session regression: OK")
    finally:
        store.close()


if __name__ == "__main__":
    verify()
