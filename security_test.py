#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline tests for the proxypool hardening change. Uses no remote services."""
import asyncio
import os
import sqlite3
from contextlib import closing
import ssl
import tempfile
import unittest

import poolsd
import poolclient


class FakeWriter:
    def __init__(self):
        self.buf = b""

    def write(self, data):
        self.buf += data

    async def drain(self):
        pass

    def close(self):
        pass


class Tests(unittest.TestCase):
    @staticmethod
    def make_app(path):
        cfg = poolsd.deep_merge(poolsd.DEFAULT_CONFIG, {
            "storage": {"db": path, "persist_credentials": False},
            "checker": {"enabled": False, "interval": 0, "startup_sweep": False},
        })
        return poolsd.App(cfg)

    def test_tls_verification(self):
        ctx = poolsd.verified_tls_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_sqlite_excludes_new_passwords_and_private_source_restores_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pool.db")
            entry = {"scheme": "http", "host": "proxy.invalid", "port": 8080,
                     "user": "privateuser", "password": "privatepass"}
            app = self.make_app(path)
            app.pool.add_many([entry])
            self.assertEqual(app.pool.proxies[0].password, "privatepass")
            with closing(sqlite3.connect(path)) as connection:
                stored = connection.execute(
                    "SELECT user,password FROM proxies LIMIT 1").fetchone()
            self.assertEqual(stored, ("", ""))
            app.store.close()
            app2 = self.make_app(path)
            self.assertEqual(app2.pool.proxies[0].password, "")
            app2.pool.add_many([entry])
            self.assertEqual(app2.pool.proxies[0].password, "privatepass")
            app2.store.close()

    def test_api_masks_list_and_protects_authenticated_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.make_app(os.path.join(tmp, "pool.db"))
            app.pool.add_many([{"scheme": "http", "host": "proxy.invalid", "port": 8080,
                                "user": "privateuser", "password": "privatepass"}])
            data = asyncio.run(app.api._route("GET", "/all", {}, {}))
            self.assertNotIn(b"privatepass", data)
            self.assertNotIn(b"privateuser", data)
            denied = asyncio.run(app.api._route("GET", "/get", {}, {}))
            self.assertTrue(denied.startswith(b"HTTP/1.1 403"))
            app.api.token = "local-test-token"
            authorized = asyncio.run(app.api._route("GET", "/get", {}, {}))
            self.assertTrue(authorized.startswith(b"HTTP/1.1 200"))
            self.assertIn(b"privatepass", authorized)
            app.store.close()

    def test_non_idempotent_methods_are_not_replayed(self):
        class StubGateway(poolsd.Gateway):
            def __init__(self, cfg, pool, checker):
                super().__init__(cfg, pool, checker)
                self.calls = 0

            async def _forward_once(self, proxy, target, method, headers, body):
                self.calls += 1
                return (503, b"HTTP/1.1 503 Service Unavailable\r\n"
                        b"Content-Length: 0\r\n\r\n", 1.0)

        with tempfile.TemporaryDirectory() as tmp:
            app = self.make_app(os.path.join(tmp, "pool.db"))
            app.pool.add_many([{"scheme": "http", "host": "proxy.invalid", "port": 8080}])
            proxy = app.pool.proxies[0]
            for method, expected in (("POST", 1), ("PUT", 1), ("PATCH", 1),
                                     ("DELETE", 1), ("GET", 1), ("HEAD", 1)):
                proxy.state = "alive"
                proxy.consec_fail = 0
                gateway = StubGateway(app.cfg, app.pool, app.checker)
                writer = FakeWriter()
                asyncio.run(gateway._do_forward(
                    f"{method} http://example.invalid/path HTTP/1.1",
                    [], None, writer))
                self.assertEqual(gateway.calls, expected, method)
            app.store.close()

    def test_gateway_context_restores_all_environment_variables(self):
        keys = poolclient.GatewaySession.KEYS
        previous = {k: os.environ.get(k) for k in keys}
        try:
            os.environ["NO_PROXY"] = "internal.example"
            os.environ.pop("no_proxy", None)
            os.environ["PROXYPOOL_GATEWAY_AUTH"] = "old"
            before = {k: os.environ.get(k) for k in keys}
            with poolclient.GatewaySession(auth="new"):
                self.assertEqual(os.environ["PROXYPOOL_GATEWAY_AUTH"], "new")
                self.assertEqual(os.environ["NO_PROXY"], "127.0.0.1,localhost")
            self.assertEqual({k: os.environ.get(k) for k in keys}, before)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_client_callback_does_not_retry_without_safe_method(self):
        class Client:
            def __init__(self):
                self.calls = 0

            def get(self, session=None, exclude_ids=None):
                self.calls += 1
                for pid in (1, 2, 3):
                    if pid not in (exclude_ids or set()):
                        return {"id": pid, "url": f"http://proxy{pid}.invalid:8080"}
                raise poolclient.NoProxyAvailable("all unique proxies exhausted")

            def report(self, *args, **kwargs):
                pass

        class Response:
            status_code = 503

        client = Client()
        calls = []
        def callback(url, ident):
            calls.append(ident)
            return Response()

        result = poolclient.request_with_rotation(callback, client, attempts=3, backoff=0)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(len(calls), 1)
        calls.clear()
        poolclient.request_with_rotation(callback, client, method="GET", attempts=3, backoff=0)
        self.assertEqual(calls, [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
