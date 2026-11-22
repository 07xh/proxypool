"""Offline regression tests for isolated direct TLS node metadata."""
import json
import tempfile
import unittest
from pathlib import Path

from direct_nodes import DirectNodeStore, parse_nodes

HOST = "kyfw.12306.cn"


class DirectNodeTests(unittest.TestCase):
    def test_import_dedup_and_reject_nonproxy(self):
        text = ("ip,port,sni,latency_ms,response_bytes\n"
                "60.26.220.61,443,kyfw.12306.cn,459.7,65960\n"
                "60.26.220.61,443,kyfw.12306.cn,400,65960\n"
                "127.0.0.1,443,kyfw.12306.cn,10,30\n"
                "60.26.220.62,443,evil.example,20,30\n")
        nodes, info = parse_nodes(text, [HOST])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].latency_ms, 400)
        self.assertEqual(info, {"invalid": 2, "duplicate": 1, "parsed": 4})
        self.assertFalse(nodes[0].as_dict()["is_proxy"])

    def test_json_timestamp_and_stale_failclosed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nodes.json"
            path.write_text(json.dumps({
                "generated": "2020-01-01T00:00:00Z",
                "nodes": [{"ip": "60.26.220.61", "port": 443, "sni": HOST,
                           "latency_ms": 450, "response_bytes": 65500}]
            }), encoding="utf-8")
            store = DirectNodeStore({"path": str(path), "allowed_hosts": [HOST]})
            self.assertEqual(store.stats()["total"], 1)
            self.assertFalse(store.stats()["fresh"])
            self.assertIsNone(store.get(HOST))
            self.assertEqual(len(store.all()), 1)
            self.assertIsNone(store.get("evil.example"))

    def test_txt_import_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "direct_nodes.local.txt"
            path.write_text("60.26.220.61,443,kyfw.12306.cn,459.7,65960\n", encoding="utf-8")
            store = DirectNodeStore({"path": str(path), "allowed_hosts": [HOST]})
            self.assertTrue(store.stats()["fresh"])
            self.assertEqual(store.get(HOST)["ip"], "60.26.220.61")
            path.write_text("127.0.0.1,443,kyfw.12306.cn,1,100\n", encoding="utf-8")
            self.assertIn("no valid", store.reload()["error"])
            self.assertIsNone(store.get(HOST))

    def test_empty_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DirectNodeStore({"path": str(Path(tmp) / "missing")})
            self.assertEqual(store.stats()["total"], 0)
            self.assertIsNone(store.get(HOST))


if __name__ == "__main__":
    unittest.main()
