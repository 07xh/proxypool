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

if __name__ == "__main__":
    unittest.main()
