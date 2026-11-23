#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline regression for independent configuration instances and local path roots."""
from __future__ import annotations

import copy
import os
from unittest.mock import patch

import poolsd


def main() -> int:
    baseline = copy.deepcopy(poolsd.DEFAULT_CONFIG)

    # A missing config file and environment overrides must never mutate defaults.
    with patch.dict(os.environ, {
        "PROXYPOOL_API_PORT": "19081",
        "PROXYPOOL_GATEWAY_PORT": "19080",
        "PROXYPOOL_DB": "alternate.db",
    }, clear=True):
        first = poolsd.load_config(None)
        assert first["api"]["port"] == 19081
        assert first["gateway"]["port"] == 19080
        assert first["storage"]["db"] == "alternate.db"
        first["checker"]["targets"].append("http://example.invalid")
        first["sources"].append({"type": "file", "path": "injected.txt"})

    with patch.dict(os.environ, {}, clear=True):
        second = poolsd.load_config(None)
    assert second["api"]["port"] == baseline["api"]["port"]
    assert second["gateway"]["port"] == baseline["gateway"]["port"]
    assert second["storage"]["db"] == baseline["storage"]["db"]
    assert second["checker"]["targets"] == baseline["checker"]["targets"]
    assert second["sources"] == baseline["sources"]
    assert poolsd.DEFAULT_CONFIG == baseline
    print("[PASS] configuration instances are independent")

    root = os.path.abspath(os.path.join(os.getcwd(), "example-app-data"))
    cfg = copy.deepcopy(baseline)
    absolute = os.path.abspath(os.path.join(os.getcwd(), "external-proxies.txt"))
    cfg["sources"] = [
        {"type": "file", "name": "relative", "path": "proxies.local.txt"},
        {"type": "file", "name": "absolute", "path": absolute},
        {"type": "url", "name": "remote", "url": "https://example.invalid/list.txt"},
    ]
    before = copy.deepcopy(cfg)
    previous_cwd = os.getcwd()
    resolved = poolsd.resolve_runtime_paths(cfg, root)
    assert resolved["storage"]["db"] == os.path.join(root, "proxies.db")
    assert resolved["direct_nodes"]["path"] == os.path.join(root, "direct_nodes.local.txt")
    assert resolved["sources"][0]["path"] == os.path.join(root, "proxies.local.txt")
    assert resolved["sources"][1]["path"] == absolute
    assert resolved["sources"][2]["url"] == "https://example.invalid/list.txt"
    assert cfg == before, "the original configuration must not be mutated"
    assert os.getcwd() == previous_cwd, "path resolving must never change global cwd"
    print("[PASS] desktop paths are anchored without changing process cwd")
    print("[PASS] all config/path tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
