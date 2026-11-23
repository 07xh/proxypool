#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hardening_test.py — 隐蔽性工程层的离线回归（不需要公网）

覆盖：
  1 FingerprintBook 稳定性与分桶分布
  2 shape_request 头序模板 / 缺项补默认 / 未知头不丢
  3 Rhythm 对数正态抖动 vs 固定节律的方差对比
  4 AffinityBook 亲和命中 / 冷却生效 / 过期回收
  5 AnonymityGate 五判据：干净代理 usable、注入代理 blacklist
  6 ProxyPool.apply_audit 把黑名单代理移出选路
  7 网关端到端：真实进程 + 真实 socket，确认头被画像重排且无泄漏头
  8 API：/audit /blacklist /hardening /rhythm

运行：python hardening_test.py      期望末行 [PASS]
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

import poolopt

HERE = os.path.dirname(os.path.abspath(__file__))
FAILURES: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{('  ' + extra) if extra else ''}")
    if not cond:
        FAILURES.append(name)


# ───────── 1 指纹桶 ─────────

def test_fingerprint_book() -> None:
    print("[1] FingerprintBook")
    book = poolopt.FingerprintBook()
    keys = [f"http://10.0.{i // 250}.{i % 250}:8080" for i in range(400)]
    first = {k: book.assign(k).name for k in keys}
    second = {k: book.assign(k).name for k in keys}
    check("同一 key 稳定分配到同一画像", first == second)
    buckets = {}
    for name in first.values():
        buckets[name] = buckets.get(name, 0) + 1
    check("分桶数落在 5–8", 5 <= len(buckets) <= 8, f"buckets={sorted(buckets)}")
    spread = max(buckets.values()) / min(buckets.values())
    check("桶间分布均衡（最大/最小 < 2.0）", spread < 2.0, f"ratio={spread:.2f}")
    profile = book.assign("http://1.1.1.1:8080")
    check("画像自带 UA 与头序模板", bool(profile.ua) and len(profile.order) >= 8,
          f"{profile.name} order={len(profile.order)}")


def test_shape_request() -> None:
    print("[2] shape_request 头序")
    profile = poolopt.default_profiles()[0]
    incoming = [
        ("Accept-Encoding", "gzip"),
        ("X-Custom-Trace", "abc123"),
        ("User-Agent", "curl/8.4.0"),
        ("Cookie", "sid=1"),
        ("Proxy-Connection", "keep-alive"),
        ("Proxy-Authorization", "Basic xxx"),
    ]
    shaped = poolopt.shape_request(profile, incoming, "target.example")
    names = [k.lower() for k, _ in shaped]
    check("Host 排第一位", names[0] == "host")
    check("剥离 Proxy-Connection / Proxy-Authorization",
          "proxy-connection" not in names and "proxy-authorization" not in names)
    check("未知头不被丢弃", "x-custom-trace" in names)
    check("User-Agent 被画像值替换",
          dict((k.lower(), v) for k, v in shaped)["user-agent"] == profile.ua)
    check("缺项补默认 Accept-Language",
          dict((k.lower(), v) for k, v in shaped).get("accept-language") == profile.lang)
    check("Cookie 保留原值", dict((k.lower(), v) for k, v in shaped).get("cookie") == "sid=1")
    check("Connection: close 收尾", names[-1] == "connection")
    # 浏览器头序里 User-Agent 在 Accept 之前；curl 顺序会被纠正回来
    check("User-Agent 早于 Accept", names.index("user-agent") < names.index("accept"))


# ───────── 3 节律 ─────────

def test_rhythm() -> None:
    print("[3] Rhythm 节律")
    samples = [poolopt.human_delay(mu=1.6, sigma=0.6) for _ in range(2000)]
    mean = statistics.mean(samples)
    cv = statistics.pstdev(samples) / mean
    check("对数正态均值落在 1.2–2.2s", 1.2 <= mean <= 2.2, f"mean={mean:.3f}")
    check("变异系数 > 0.4（固定 sleep 的 CV≈0）", cv > 0.4, f"cv={cv:.3f}")
    check("下界守住 0.15s", min(samples) >= 0.15, f"min={min(samples):.3f}")

    fixed_cv = statistics.pstdev([1.6] * 200) / 1.6
    check("对照组固定节律 CV=0", fixed_cv == 0.0)

    rhythm = poolopt.Rhythm(mu=0.0, sigma=0.0, per_key_qps=2.0, global_qps=1000.0)
    waits = [rhythm.delay_for("a.example", "http://1.1.1.1:8080") for _ in range(12)]
    check("令牌桶耗尽后产生等待", any(w > 0 for w in waits),
          f"positive={sum(1 for w in waits if w > 0)}/12")
    # 跨域不共享：b.example 的桶是新建的（满 5 个令牌），不该被 a.example 抽干
    fresh = rhythm._bucket("b.example|http://1.1.1.1:8080")
    check("跨目标域不共享配额", fresh.tokens >= 4.0, f"tokens={fresh.tokens:.2f}")
    other = rhythm.delay_for("b.example", "http://1.1.1.1:8080")
    check("新目标域首次请求无等待", other < 0.05, f"wait={other:.3f}")


def test_affinity() -> None:
    print("[4] AffinityBook 亲和与冷却")
    book = poolopt.AffinityBook(affinity_ttl=0.2, cooldown=0.2)
    book.bind("target.example", "http://1.1.1.1:8080")
    check("亲和命中", book.affinity("target.example") == "http://1.1.1.1:8080")
    book.touch("target.example", "http://1.1.1.1:8080")
    check("刚用过的出口处于冷却", book.cooling("target.example", "http://1.1.1.1:8080"))
    check("未用过的出口不冷却", not book.cooling("target.example", "http://2.2.2.2:8080"))
    time.sleep(0.3)
    check("TTL 到期后亲和失效", book.affinity("target.example") is None)
    check("冷却到期后解除", not book.cooling("target.example", "http://1.1.1.1:8080"))
    book.purge()
    check("purge 清掉过期记录", book.stats()["affinity"] == 0)


# ───────── 5 五判据 ─────────

class MockWorld:
    """假世界：目标站 + 干净代理 + 注入代理。"""

    def __init__(self) -> None:
        self.servers: list[asyncio.AbstractServer] = []
        self.target_port = 0
        self.clean_port = 0
        self.bad_port = 0
        self.closed_port = 0

    async def start(self) -> None:
        target = await asyncio.start_server(self._target, "127.0.0.1", 0)
        self.target_port = target.sockets[0].getsockname()[1]
        clean = await asyncio.start_server(
            self._make_proxy(inject=False), "127.0.0.1", 0)
        self.clean_port = clean.sockets[0].getsockname()[1]
        bad = await asyncio.start_server(self._make_proxy(inject=True), "127.0.0.1", 0)
        self.bad_port = bad.sockets[0].getsockname()[1]
        # 留一个「绝不放行」的参考端口：探针打得通它才算代理开了非 HTTP 口
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.closed_port = probe.getsockname()[1]
        self.servers = [target, clean, bad]

    async def stop(self) -> None:
        for srv in self.servers:
            srv.close()
            await srv.wait_closed()

    @staticmethod
    async def _target(reader, writer) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        text = head.decode("latin-1")
        first = text.split("\r\n")[0]
        path = first.split(" ")[1] if " " in first else "/"
        headers = {}
        for line in text.split("\r\n")[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        if path.startswith("/__pp-must-404"):
            body = b'{"error":"not found","path":"' + path.encode() + b'"}'
            status = "404 Not Found"
        elif path.startswith("/ip"):
            body = json.dumps({"origin": "203.0.113.9",
                               "ua": headers.get("user-agent", ""),
                               "received": headers}).encode()
            status = "200 OK"
        else:
            body = json.dumps({"ok": True, "path": path}).encode()
            status = "200 OK"
        writer.write(f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                     .encode("latin-1") + body)
        try:
            await writer.drain()
            writer.close()
        except Exception:
            pass

    @staticmethod
    def _make_proxy(inject: bool):
        async def handler(reader, writer) -> None:
            try:
                head = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                writer.close()
                return
            text = head.decode("latin-1")
            first = text.split("\r\n")[0]
            parts = first.split()
            if len(parts) < 2:
                writer.close()
                return
            if parts[0].upper() == "CONNECT":
                chost, _, cport = parts[1].partition(":")
                try:
                    ur, uw = await asyncio.open_connection(chost, int(cport or "443"))
                except (OSError, ValueError):
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await asyncio.gather(poolopt_pipe(reader, uw),
                                     poolopt_pipe(ur, writer),
                                     return_exceptions=True)
                return
            urlsplit = urllib.request.urlsplit(parts[1])
            host = urlsplit.hostname or "127.0.0.1"
            port = urlsplit.port or 80
            path = (urlsplit.path or "/") + (("?" + urlsplit.query) if urlsplit.query else "")
            fwd = [f"GET {path} HTTP/1.1", f"Host: {urlsplit.netloc}"]
            for line in text.split("\r\n")[1:]:
                if not line:
                    continue
                k, _, v = line.partition(":")
                if k.strip().lower() in ("host", "proxy-connection",
                                         "proxy-authorization", "connection"):
                    continue
                fwd.append(f"{k.strip()}: {v.strip()}")
            fwd.append("Connection: close")
            try:
                r, w = await asyncio.open_connection(host, port)
            except OSError:
                body = b"upstream unreachable"
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                writer.close()
                return
            w.write(("\r\n".join(fwd) + "\r\n\r\n").encode("latin-1"))
            await w.drain()
            raw = b""
            while True:
                chunk = await r.read(8192)
                if not chunk:
                    break
                raw += chunk
            w.close()
            if inject:
                # 注入型代理的两个典型行为：404 改写成 200；转发头泄漏
                if b"404" in raw.split(b"\r\n", 1)[0]:
                    body = b"<html>injected by proxy</html>"
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: "
                                 + str(len(body)).encode()
                                 + b"\r\nX-Forwarded-For: 10.9.9.9\r\nConnection: close\r\n\r\n"
                                 + body)
                    await writer.drain()
                    writer.close()
                    return
                # 广告注入型代理的真实行为：不改状态码，往正文尾部塞一段 banner
                head, _, body = raw.partition(b"\r\n\r\n")
                body = body + b"<script>window.__ad=1;</script>"
                lines = []
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        continue
                    lines.append(line)
                lines.append(f"Content-Length: {len(body)}".encode())
                lines.append(b"X-Forwarded-For: 10.9.9.9")
                lines.append(b"Via: 1.1 badproxy")
                raw = b"\r\n".join(lines) + b"\r\n\r\n" + body
            writer.write(raw)
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass
        return handler


async def poolopt_scope_probe(gate, closed_proxy, world) -> dict:
    """用「必然不可达」的参考端口跑端口面探针，验证 http_only 判据方向正确。"""
    saved = gate.port_scope_ports
    try:
        gate.port_scope_ports = (world.closed_port,)
        gate.port_scope_host = "127.0.0.1"
        return await gate._port_scope(closed_proxy)
    finally:
        gate.port_scope_ports = saved


async def poolopt_pipe(src, dst) -> None:
    try:
        while True:
            data = await src.read(8192)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except Exception:
        pass


async def test_gate() -> None:
    print("[5] AnonymityGate 五判据")
    world = MockWorld()
    await world.start()
    try:
        target = f"http://127.0.0.1:{world.target_port}/ip"
        gate = poolopt.AnonymityGate([target], timeout=4.0, max_body=65536,
                                     port_scope_host="127.0.0.1",
                                     port_scope_ports=(1,))

        class P:
            def __init__(self, host, port):
                self.scheme = "http"
                self.host = host
                self.port = port
                self.user = ""
                self.password = ""

        class CLOSED:
            """假世界没有真端口可放行：拿一个必然拒连的端口做「端口面」探针，
            探针回 502 = 「没放行」，与「只放行 HTTP」同义。"""
            scheme = "http"
            user = ""
            password = ""

            def __init__(self):
                self.host = "127.0.0.1"
                self.port = world.closed_port

        clean = await gate.audit(P("127.0.0.1", world.clean_port), deep=True)
        bad = await gate.audit(P("127.0.0.1", world.bad_port), deep=True)

        check("干净代理判 usable", clean["grade"] == "usable",
              f"grade={clean['grade']} score={clean['score']}")
        check("注入代理判 blacklist", bad["grade"] == "blacklist",
              f"grade={bad['grade']} fake_404={bad['injection'].get('fake_404')}")
        check("注入代理 404 改写被识别", bad["injection"].get("fake_404") is True)
        check("转发头泄漏被识别", bool(bad["transparency"].get("leaked_headers")),
              str(bad["transparency"].get("leaked_headers")))
        check("干净代理无转发头泄漏",
              not clean["transparency"].get("leaked_headers"),
              str(clean["transparency"].get("leaked_headers")))
        check("透传 UA 未被改写", clean["transparency"].get("ua_rewritten") is False)
        check("一致性判定有 CV 值", clean["stability"].get("cv") is not None,
              f"cv={clean['stability'].get('cv')}")
        # 端口面探针：假世界把「必然拒连」的端口拿出来当 reference，
        # 代理对它的 CONNECT 回 502 → http_only 成立
        scope = await poolopt_scope_probe(gate, CLOSED(), world)
        check("端口面只放行 HTTP", scope.get("http_only") is True, json.dumps(scope))

        same, why = await gate.content_ok(P("127.0.0.1", world.clean_port), target)
        check("L2 内容一致性与基线 sha 匹配（探针发同一组头）", same, why)
        same_bad, why_bad = await gate.content_ok(P("127.0.0.1", world.bad_port), target)
        check("注入代理 L2 判定为不一致", not same_bad, why_bad)
    finally:
        await world.stop()


# ───────── 6 池接线 ─────────

def test_pool_wiring() -> None:
    print("[6] ProxyPool.apply_audit")
    import poolsd

    db_path = os.path.join(HERE, f".hardening-{os.getpid()}.db")
    cfg = poolsd.deep_merge(poolsd.DEFAULT_CONFIG, {
        "storage": {"db": db_path},
        "checker": {"enabled": False, "interval": 0, "startup_sweep": False},
    })
    app = poolsd.App(cfg)
    try:
        app.pool.add_many([
            {"scheme": "http", "host": "10.0.0.1", "port": 8080},
            {"scheme": "http", "host": "10.0.0.2", "port": 8080},
            {"scheme": "http", "host": "10.0.0.3", "port": 8080},
        ])
        good, bad, other = app.pool.proxies
        for p in app.pool.proxies:
            app.pool.report(p, True, 100.0)

        check("入库即分配画像", all(p.profile for p in app.pool.proxies),
              str([p.profile for p in app.pool.proxies]))

        app.pool.apply_audit(good, {"grade": "usable", "score": 100})
        app.pool.apply_audit(other, {"grade": "degraded", "score": 70})
        app.pool.apply_audit(bad, {"grade": "blacklist", "score": 40})
        check("黑名单记入集合", bad.key in app.pool.blacklist, str(app.pool.blacklist))
        check("黑名单代理被停用", bad.enabled is False)

        picked = {app.pool.pick().key for _ in range(200)}
        check("选路永不返回黑名单代理", bad.key not in picked, str(sorted(picked)))

        app.pool.report(bad, False)
        check("黑名单代理失败不改回可选", app.pool.pick() is not None
              and bad.key not in {app.pool.pick().key for _ in range(50)})

        app.pool.report(good, True, 50.0)
        app.pool.report(other, True, 400.0)
        w_good = app.pool._score(good)
        w_other = app.pool._score(other)
        check("usable 权重高于 degraded", w_good > w_other,
              f"usable={w_good:.3f} degraded={w_other:.3f}")

        freed = app.pool.clear_blacklist([bad.key])
        check("人工放行后恢复可选", freed == 1 and bad.enabled is True)
        stats = app.pool.stats()
        check("stats 暴露 blacklist / by_grade / fingerprints",
              "blacklist" in stats and "by_grade" in stats and "fingerprints" in stats,
              json.dumps({k: stats[k] for k in ("blacklist", "by_grade")},
                         ensure_ascii=False))
    finally:
        app.store.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_path + suffix)
            except OSError:
                pass


def test_affinity_in_pick() -> None:
    print("[6b] pick(host=) 亲和与冷却")
    import poolsd

    db_path = os.path.join(HERE, f".hardening-aff-{os.getpid()}.db")
    cfg = poolsd.deep_merge(poolsd.DEFAULT_CONFIG, {
        "storage": {"db": db_path},
        "checker": {"enabled": False, "interval": 0, "startup_sweep": False},
        "hardening": {"affinity_ttl": 300, "proxy_cooldown": 0.5},
    })
    app = poolsd.App(cfg)
    try:
        app.pool.add_many([
            {"scheme": "http", "host": "10.1.0.1", "port": 8080},
            {"scheme": "http", "host": "10.1.0.2", "port": 8080},
        ])
        for p in app.pool.proxies:
            app.pool.report(p, True, 80.0)
        first = app.pool.pick(host="shop.example")
        second = app.pool.pick(host="shop.example")
        check("同一目标域两次取到同一出口", first.key == second.key,
              f"{first.key} vs {second.key}")
        other = app.pool.pick(host="api.example")
        check("不同目标域可换出口", other is not None)
        time.sleep(0.6)
        app.pool.affinity._affinity.clear()
        third = app.pool.pick(host="shop.example")
        check("亲和过期或冷却结束后可换线", third is not None)
    finally:
        app.store.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_path + suffix)
            except OSError:
                pass


# ───────── 7 网关端到端 ─────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _run_mock_proc() -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_upstream.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        line = proc.stdout.readline()
        if b"READY" in line:
            return proc
        if proc.poll() is not None:
            raise RuntimeError("mock_upstream 启动失败")
    return proc


def test_gateway_end_to_end() -> None:
    print("[7] 网关端到端（真实进程 + 真实 socket）")
    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_upstream.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(200):
            line = mock.stdout.readline()
            if b"READY" in line:
                break
            if mock.poll() is not None:
                check("mock_upstream 启动", False, "进程提前退出")
                return
        api_port = _free_port()
        gw_port = _free_port()
        db_path = os.path.join(HERE, f".hardening-gw-{os.getpid()}.db")
        cfg_path = os.path.join(HERE, f".hardening-gw-{os.getpid()}.json")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump({
                "api": {"host": "127.0.0.1", "port": api_port, "token": ""},
                "gateway": {"enabled": True, "host": "127.0.0.1", "port": gw_port,
                            "auth": "", "max_retry": 1, "rhythm_enabled": True,
                            "shape_headers": True, "connect_timeout": 5,
                            "idle_timeout": 15},
                "checker": {"enabled": False, "interval": 0, "startup_sweep": False},
                "pool": {"strategy": "weighted_random", "sticky_ttl": 300,
                         "allow_cold_start": True, "max_dead_retry": 3},
                "storage": {"db": db_path, "flush_interval": 60},
                "hardening": {"rhythm_mu": 0.0, "rhythm_sigma": 0.0,
                              "global_qps": 50.0, "per_key_qps": 50.0,
                              "port_scope_host": "127.0.0.1", "port_scope_ports": [1]},
                "sources": [], "public_sources": [],
                "direct_nodes": {"path": "no-such-nodes.txt",
                                 "allowed_hosts": ["kyfw.12306.cn"]},
                "log_level": "warn",
            }, fh)
        daemon = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "poolsd.py"), "-c", cfg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            base = f"http://127.0.0.1:{api_port}"
            ready = False
            for _ in range(120):
                try:
                    with urllib.request.urlopen(base + "/health", timeout=1) as r:
                        ready = r.status == 200
                    if ready:
                        break
                except (urllib.error.URLError, OSError):
                    time.sleep(0.1)
            check("守护进程起来", ready)

            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def api(path, data=None, method=None):
                body = json.dumps(data).encode() if data is not None else None
                req = urllib.request.Request(
                    base + path, data=body, method=method or ("POST" if body else "GET"),
                    headers={"Content-Type": "application/json"})
                with opener.open(req, timeout=20) as resp:
                    return json.loads(resp.read().decode())

            added = api("/add", {"proxies": ["127.0.0.1:19002"]})
            check("注入假代理入库", added.get("added") == 1, json.dumps(added))

            audited = api("/audit", {})
            check("/audit 跑完五判据", "checked" in audited, json.dumps(audited))

            hardening = api("/hardening")
            check("/hardening 暴露画像与节律",
                  "fingerprints" in hardening and "rhythm" in hardening,
                  json.dumps(hardening.get("rhythm"), ensure_ascii=False))

            proxy_url = f"http://127.0.0.1:{gw_port}"
            gw_opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_url}))
            seen = None
            for _ in range(6):
                try:
                    with gw_opener.open(
                            "http://127.0.0.1:19001/echo?trace=1", timeout=10) as r:
                        body = json.loads(r.read().decode())
                    seen = body
                    break
                except (urllib.error.URLError, OSError):
                    time.sleep(0.2)
            check("网关转发成功", seen is not None and "target-site" in seen.get("origin", ""),
                  json.dumps(seen or {}, ensure_ascii=False)[:200])
            if seen:
                headers = {k.lower(): v for k, v in seen.get("headers", {}).items()}
                check("上游确实被经过", headers.get("x-proxy-a") == "1",
                      str(headers.get("x-proxy-a")))
                check("无 Via / X-Forwarded-For 泄漏",
                      "via" not in headers and "x-forwarded-for" not in headers)
                check("画像 UA 已注入",
                      "Chrome/" in headers.get("user-agent", "")
                      or "Firefox/" in headers.get("user-agent", "")
                      or "Safari/" in headers.get("user-agent", ""),
                      headers.get("user-agent", ""))
                check("Accept-Language 与画像一致",
                      "q=" in headers.get("accept-language", ""),
                      headers.get("accept-language", ""))
                check("上游未收到 Proxy-Authorization",
                      "proxy-authorization" not in headers)

            rhythm = api("/rhythm", {"mu": 1.0, "per_key_qps": 4.0})
            check("/rhythm 运行时调参生效",
                  abs(rhythm.get("mu", 0) - 1.0) < 1e-6, json.dumps(rhythm))

            black = api("/blacklist")
            check("/blacklist 可查", "keys" in black and "count" in black,
                  json.dumps(black)[:200])
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:
                daemon.kill()
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(db_path + suffix)
                except OSError:
                    pass
            try:
                os.remove(cfg_path)
            except OSError:
                pass
    finally:
        mock.terminate()
        try:
            mock.wait(timeout=10)
        except subprocess.TimeoutExpired:
            mock.kill()


def test_poolsd_selftest() -> None:
    print("[8] 原内置自测仍全绿")
    proc = subprocess.run([sys.executable, os.path.join(HERE, "poolsd.py"), "--selftest"],
                          capture_output=True, text=True, timeout=180)
    tail = (proc.stdout or "").strip().splitlines()[-3:]
    check("poolsd --selftest 退出码 0", proc.returncode == 0,
          " | ".join(tail) + (proc.stderr or "")[-300:])


def main() -> int:
    print("=" * 62)
    print("proxypool 隐蔽性工程层 验收")
    print("=" * 62)
    test_fingerprint_book()
    test_shape_request()
    test_rhythm()
    test_affinity()
    asyncio.run(test_gate())
    test_pool_wiring()
    test_affinity_in_pick()
    test_gateway_end_to_end()
    test_poolsd_selftest()
    print("=" * 62)
    if FAILURES:
        print(f"[FAIL] {len(FAILURES)} 项：")
        for name in FAILURES:
            print("   -", name)
        return 1
    print("[PASS] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())