#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local TLS endpoint directory, deliberately separate from HTTP/SOCKS proxies.

Entries are imported observations, not independently re-verified live nodes.
Never pass these endpoints to HTTP_PROXY/HTTPS_PROXY or the proxy scheduler.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import time
from typing import Any

_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
_MAX_ENTRIES = 20000


@dataclass(frozen=True)
class DirectNode:
    ip: str
    port: int
    sni: str
    latency_ms: float
    response_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {"type": "direct_tls", **asdict(self), "is_proxy": False}


def _valid_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if not _HOST_RE.fullmatch(host) or ".." in host or "." not in host:
        raise ValueError("invalid SNI hostname")
    return host


def parse_nodes(text: str, allowed_hosts: list[str]) -> tuple[list[DirectNode], dict[str, int]]:
    """Parse ip,port,sni,latency_ms,response_bytes CSV or JSON results."""
    allowed = {_valid_host(s) for s in allowed_hosts}
    if not allowed:
        raise ValueError("direct_nodes.allowed_hosts cannot be empty")
    text = text.lstrip("\ufeff").strip()
    rows: list[Any]
    if text.startswith("[") or text.startswith("{"):
        data = json.loads(text)
        rows = data.get("nodes", data.get("direct_nodes", [])) if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise ValueError("nodes must be a list")
    else:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split(",")]
            if parts[0].lower() in ("ip", "address"):
                continue
            rows.append(parts)
    if len(rows) > _MAX_ENTRIES:
        raise ValueError("too many direct nodes")
    selected: dict[tuple[str, int, str], DirectNode] = {}
    invalid = 0
    duplicates = 0
    for row in rows:
        try:
            if isinstance(row, dict):
                ip, port, sni = row["ip"], row.get("port", 443), row["sni"]
                latency = row.get("latency_ms", row.get("latency", row.get("rtt_ms")))
                size = row.get("response_bytes", row.get("bytes", 0))
            else:
                if not isinstance(row, list) or len(row) < 4:
                    raise ValueError("bad row")
                ip, port, sni, latency = row[:4]
                size = row[4] if len(row) > 4 else 0
            address = ipaddress.ip_address(str(ip).strip())
            if address.version != 4 or not address.is_global:
                raise ValueError("non-public IPv4")
            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError("invalid port")
            host = _valid_host(str(sni))
            if host not in allowed:
                raise ValueError("host not on allowlist")
            latency = float(str(latency).strip().removesuffix("ms").strip())
            size = int(size)
            if not (0 <= latency <= 600000 and 0 <= size <= 100000000):
                raise ValueError("invalid measurements")
            node = DirectNode(str(address), port, host, latency, size)
            key = (node.ip, node.port, node.sni)
            if key in selected:
                duplicates += 1
                if node.latency_ms >= selected[key].latency_ms:
                    continue
            selected[key] = node
        except (ValueError, TypeError, KeyError, OverflowError):
            invalid += 1
    return sorted(selected.values(), key=lambda n: (n.latency_ms, n.ip)), {
        "invalid": invalid, "duplicate": duplicates, "parsed": len(rows)
    }


def _parse_generated(text: str, fallback_timestamp: float) -> float:
    """Prefer exported JSON timestamp; fall back to local file modified time."""
    try:
        data = json.loads(text)
        if isinstance(data, dict) and data.get("generated"):
            raw = data["generated"]
            if isinstance(raw, (int, float)):
                return float(raw)
            if isinstance(raw, str):
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        pass
    return fallback_timestamp


class DirectNodeStore:
    """Read-only local directory; reload is explicitly requested via the API."""

    def __init__(self, config: dict[str, Any]):
        self.path = Path(config.get("path", "direct_nodes.local.txt"))
        self.allowed_hosts = [_valid_host(s) for s in config.get("allowed_hosts", ["kyfw.12306.cn"])]
        self.max_age_seconds = max(60, float(config.get("max_age_hours", 72)) * 3600)
        self.nodes: list[DirectNode] = []
        self.generated_at: float | None = None
        self.errors: dict[str, int] = {}
        self.error: str | None = None
        self.reload()

    def reload(self) -> dict[str, Any]:
        if not self.path.is_file():
            self.nodes = []
            self.generated_at = None
            self.errors = {}
            self.error = None
            return self.stats()
        try:
            if self.path.stat().st_size > 2_000_000:
                raise ValueError("direct node file is too large")
            text = self.path.read_text(encoding="utf-8-sig")
            nodes, errors = parse_nodes(text, self.allowed_hosts)
            if text.strip() and not nodes:
                raise ValueError("no valid direct nodes (check allowlisted SNI and CSV fields)")
            self.nodes = nodes
            self.generated_at = _parse_generated(text, self.path.stat().st_mtime)
            self.errors = errors
            self.error = None
        except (OSError, ValueError, UnicodeError) as exc:
            self.error = str(exc)
            self.nodes = []
            self.generated_at = None
            self.errors = {}
        return self.stats()

    def is_fresh(self) -> bool:
        return bool(self.generated_at is not None and
                    0 <= time.time() - self.generated_at <= self.max_age_seconds)

    def stats(self) -> dict[str, Any]:
        return {
            "type": "direct_tls", "total": len(self.nodes),
            "fresh": self.is_fresh(),
            "generated_at": (datetime.fromtimestamp(self.generated_at, timezone.utc).isoformat()
                             if self.generated_at is not None else None),
            "max_age_hours": self.max_age_seconds / 3600,
            "allowed_hosts": self.allowed_hosts,
            "source": str(self.path), "parse": self.errors,
            "error": self.error, "live_verified": False,
        }

    def all(self, host: str | None = None) -> list[dict[str, Any]]:
        if host is not None:
            try:
                host = _valid_host(host)
            except ValueError:
                return []
        return [n.as_dict() for n in self.nodes if host is None or n.sni == host]

    def get(self, host: str) -> dict[str, Any] | None:
        try:
            host = _valid_host(host)
        except ValueError:
            return None
        if not self.is_fresh() or host not in self.allowed_hosts:
            return None
        for node in self.nodes:
            if node.sni == host:
                return node.as_dict()
        return None
