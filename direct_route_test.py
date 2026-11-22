#!/usr/bin/env python3
"""Regression of private CSV compatibility, separate routing and cooldown."""
import asyncio
import tempfile
import unittest
from pathlib import Path
from direct_nodes import DirectNodeStore, parse_nodes
from direct_route import DirectRouteManager

HOST = "kyfw.12306.cn"
A = "8.8.8.8,443,kyfw.12306.cn,75,100"
B = "1.1.1.1,443,kyfw.12306.cn,90,100"

class DirectRoutingTests(unittest.TestCase):
    def make(self, tmp):
        path = Path(tmp) / "nodes.txt"
        path.write_text(A + "\n" + B + "\n", encoding="utf-8")
        store = DirectNodeStore({"path": str(path), "allowed_hosts": [HOST]})
        route = DirectRouteManager(store, {"route_enabled": True, "max_fail": 2})
        return store, route, path

    def test_legacy_and_current_csv(self):
        text = "kyfw.12306.cn,kyfw.12306.cn,8.8.8.8,443,145,504\n" + A
        nodes, report = parse_nodes(text, [HOST])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].latency_ms, 75)
        self.assertEqual(report["duplicate"], 1)
        invalid, _ = parse_nodes("other.example,kyfw.12306.cn,8.8.8.8,443,1,10", [HOST])
        self.assertFalse(invalid)

    def test_allowlist_picker_and_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, route, path = self.make(tmp)
            self.assertTrue(route.matches(HOST))
            self.assertFalse(route.matches("other.example"))
            self.assertFalse(route.matches(HOST, 80))
            first = route.pick(HOST, set())
            second = route.pick(HOST, {route.key(first)})
            self.assertNotEqual(first, second)
            route.record(first, False)
            route.record(first, False)
            self.assertEqual(route._state(first)["state"], "cooldown")
            self.assertEqual(route.pick(HOST, set()), second)
            route.record(first, True, 22., verified_https=True)
            self.assertEqual(route.pick(HOST, set()), first)
            self.assertEqual(route.stats()["https_verified"], 1)
            route.enabled = False
            self.assertFalse(route.matches(HOST))

    def test_stale_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, route, path = self.make(tmp)
            store.generated_at = 1
            self.assertFalse(route.matches(HOST))
            self.assertEqual(route.stats()["eligible"], 0)
            path.write_text("127.0.0.1,443,kyfw.12306.cn,1,10", encoding="utf-8")
            store.reload()
            route.prune()
            self.assertFalse(route.matches(HOST))
            self.assertEqual(route.stats()["https_verified"], 0)

class DirectAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_verification_host_is_bounded_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nodes.csv"
            path.write_text(A, encoding="utf-8")
            route = DirectRouteManager(
                DirectNodeStore({"path": str(path), "allowed_hosts": [HOST]}), {})
            with self.assertRaises(ValueError):
                await route.verify(host="wrong.example")
            with self.assertRaises(ValueError):
                await route.verify(limit=0)
            self.assertEqual(route.stats()["https_verified"], 0)


class DummyWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True


class GatewayRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_uses_raw_stream_and_keeps_proxy_pool_separate(self):
        import poolsd
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nodes.txt"
            path.write_text(A + "\n", encoding="utf-8")
            cfg = poolsd.deep_merge(poolsd.DEFAULT_CONFIG, {
                "storage": {"db": ":memory:"},
                "direct_nodes": {"path": str(path), "allowed_hosts": [HOST],
                                 "route_enabled": True}})
            app = poolsd.App(cfg)
            try:
                calls = []
                async def fake_connect(node):
                    calls.append((node.ip, node.port))
                    upstream_reader = asyncio.StreamReader()
                    upstream_reader.feed_eof()
                    return upstream_reader, DummyWriter()
                app.direct_route.connect = fake_connect
                gateway = poolsd.Gateway(cfg, app.pool, app.checker, app.direct_route)
                client_reader = asyncio.StreamReader()
                client_reader.feed_eof()
                client_writer = DummyWriter()
                await gateway._do_connect(HOST + ":443", client_reader, client_writer)
                self.assertTrue(bytes(client_writer.data).startswith(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n"))
                self.assertEqual(calls, [("8.8.8.8", 443)])
                self.assertEqual(gateway.stats["direct_route_hit"], 1)
                self.assertEqual(gateway.stats["direct_route_fail"], 0)
                self.assertEqual(len(app.pool.proxies), 0)
                # TCP connect is not proof of HTTPS certificate validity.
                self.assertEqual(app.direct_route.stats()["https_verified"], 0)
            finally:
                app.store.close()

    async def test_failed_nodes_are_distinct_and_gateway_falls_back(self):
        import poolsd
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nodes.txt"
            path.write_text(A + "\n" + B + "\n", encoding="utf-8")
            cfg = poolsd.deep_merge(poolsd.DEFAULT_CONFIG, {
                "storage": {"db": ":memory:"},
                "direct_nodes": {"path": str(path), "allowed_hosts": [HOST],
                                 "route_enabled": True, "route_retry": 4}})
            app = poolsd.App(cfg)
            try:
                attempts = []
                async def always_fail(node):
                    attempts.append(node.ip)
                    raise OSError("offline fixture")
                app.direct_route.connect = always_fail
                gateway = poolsd.Gateway(cfg, app.pool, app.checker, app.direct_route)
                client_reader = asyncio.StreamReader()
                client_reader.feed_eof()
                client_writer = DummyWriter()
                await gateway._do_connect(HOST + ":443", client_reader, client_writer)
                self.assertEqual(len(attempts), 2)
                self.assertEqual(len(set(attempts)), 2)
                self.assertIn(b"502 Bad Gateway", bytes(client_writer.data))
                self.assertEqual(app.direct_route.counters["fallback"], 1)
                self.assertEqual(gateway.stats["direct_route_fail"], 2)
                self.assertFalse(app.pool.proxies)
            finally:
                app.store.close()

    async def test_direct_api_explicit_enable_and_host_rejection(self):
        import json
        import poolsd
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nodes.txt"
            path.write_text(A, encoding="utf-8")
            cfg = poolsd.deep_merge(poolsd.DEFAULT_CONFIG, {
                "storage": {"db": ":memory:"},
                "direct_nodes": {"path": str(path), "allowed_hosts": [HOST],
                                 "route_enabled": False}})
            app = poolsd.App(cfg)
            try:
                reply = await app.api._route("GET", "/direct/stats", {}, {})
                status = json.loads(reply.split(b"\r\n\r\n", 1)[1])
                self.assertFalse(status["route_enabled"])
                self.assertEqual(status["total"], 1)
                reply = await app.api._route("POST", "/direct/route", {},
                                              {"enabled": True})
                enabled = json.loads(reply.split(b"\r\n\r\n", 1)[1])
                self.assertTrue(enabled["route_enabled"])
                self.assertTrue(app.direct_route.matches(HOST))
                reply = await app.api._route("POST", "/direct/verify", {},
                                              {"host": "unapproved.example"})
                self.assertTrue(reply.startswith(b"HTTP/1.1 400 "), reply[:80])
                self.assertEqual(len(app.pool.proxies), 0)
            finally:
                app.store.close()

if __name__ == "__main__":
    unittest.main()
