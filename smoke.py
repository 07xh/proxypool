#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smoke.py — 端到端冒烟：真实进程 + 真实端口 + 真实 socket

覆盖四类宿主最常见的接入姿势：
  1. HTTP 明文转发（urllib 走 absolute-form）
  2. CONNECT 隧道（对真实 TCP 服务做字节级回读，HTTPS/WebSocket 都走这条）
  3. SOCKS5 上游（池里混入 socks5:// 代理，网关照样把它当普通上游用）
  4. 死代理换线重试（一个请求打进去，内部自动换到健康线上）

全部通过才返回 0。
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
API = "http://127.0.0.1:19081"
GATEWAY = "http://127.0.0.1:19080"
TARGET = "http://127.0.0.1:19001/echo"
DB = os.path.join(HERE, ".smoke.db")
CFG = os.path.join(HERE, ".smoke.json")


def post(path, payload):
    req = urllib.request.Request(API + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def get(path):
    with urllib.request.urlopen(API + path, timeout=10) as r:
        return r.read().decode()


def wait_port(host, port, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def tunnel_through_gateway(host, port, payload):
    """手写 CONNECT，穿过网关到目标 TCP 服务，做字节级回读。"""
    s = socket.create_connection(("127.0.0.1", 19080), timeout=10)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    if status != 200:
        s.close()
        return status, b""
    s.sendall(payload)
    out = rest
    deadline = time.time() + 8
    while len(out) < len(payload) + 5 and time.time() < deadline:
        try:
            d = s.recv(4096)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    s.close()
    return status, out


def main():
    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_upstream.py")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port("127.0.0.1", 19002):
        mock.terminate()
        print("mock upstream 起不来，检查 19001-19006 是否被占用")
        return 2

    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(DB + suffix)
        except OSError:
            pass
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump({
            "api": {"port": 19081, "token": ""},
            # This suite validates transport and failover, not request timing.
            # Keep rate-control tests in hardening_test.py to avoid random
            # long waits during the 24-request Windows CI rotation check.
            "gateway": {"enabled": True, "port": 19080, "max_retry": 2,
                        "connect_timeout": 5.0, "idle_timeout": 30.0,
                        "rhythm_enabled": False},
            "checker": {"enabled": False, "interval": 0, "startup_sweep": False,
                        "timeout": 4.0,
                        "targets": ["http://127.0.0.1:19001/echo"]},
            "pool": {"strategy": "weighted_random", "sticky_ttl": 60,
                     "allow_cold_start": True, "max_dead_retry": 2},
            "storage": {"db": DB, "flush_interval": 2},
            "sources": [],
            "log_level": "info",
        }, f)

    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "poolsd.py"), "-c", CFG],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    fails = []

    def check(name, cond, extra=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}{('  ' + extra) if extra else ''}")
        if not cond:
            fails.append(name)

    try:
        ready = False
        for _ in range(80):
            try:
                get("/health")
                ready = True
                break
            except Exception:
                time.sleep(0.3)
        check("poolsd 守护进程启动并监听", ready)

        # ——— 1. HTTP 上游池 ———
        res = post("/add", {"proxies": ["http://127.0.0.1:19002",
                                        "http://127.0.0.1:19003"]})
        check("灌入 2 条 HTTP 代理", res.get("added") == 2, json.dumps(res))
        chk = post("/check", {"scope": "all"})
        check("体检通过 2 条", chk.get("ok") == 2, json.dumps(chk))

        op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": GATEWAY}))
        seen = set()
        statuses = []
        for _ in range(24):
            with op.open(TARGET, timeout=10) as r:
                body = json.loads(r.read().decode())
                statuses.append(r.status)
                h = body.get("headers", {})
                if h.get("x-proxy-a") == "1":
                    seen.add("A")
                if h.get("x-proxy-b") == "1":
                    seen.add("B")
        check("24 发 HTTP 全部 200", all(s == 200 for s in statuses),
              f"状态码={sorted(set(statuses))}")
        check("A/B 双上游都被轮换到", seen == {"A", "B"}, f"命中={sorted(seen)}")

        # ——— 2. CONNECT 隧道（字节级回读）———
        st, data = tunnel_through_gateway("127.0.0.1", 19006, b"tunnel-ping-42")
        check("CONNECT 隧道建立成功", st == 200, f"status={st}")
        check("隧道回读到目标原始字节", data.startswith(b"ECHO:tunnel-ping-42"),
              repr(data[:40]))

        # ——— 3. 死代理换线 ———
        post("/add", {"proxies": ["http://127.0.0.1:19004"]})
        time.sleep(0.6)
        st2, data2 = tunnel_through_gateway("127.0.0.1", 19006, b"after-dead")
        check("池内混入死代理后隧道仍成功（自动换线）",
              st2 == 200 and b"ECHO:" in data2, f"status={st2}")

        # ——— 4. SOCKS5 上游 ———
        adds = post("/add", {"proxies": ["socks5://127.0.0.1:19005"]})
        check("灌入 socks5 上游", adds.get("added") == 1, json.dumps(adds))
        st3, data3 = tunnel_through_gateway("127.0.0.1", 19006, b"socks-path")
        check("socks5 上游也能承载隧道", st3 == 200 and b"ECHO:socks-path" in data3,
              f"status={st3}")

        s = json.loads(get("/stats"))
        check("池状态：新增 socks5 尚未体检时记为 new",
              s.get("alive", 0) >= 2 and "new" in s["by_state"],
              f"by_state={s['by_state']}")

        # 复检到底：死代理在 max_dead_retry=2 时需连续两次失败才落到 dead
        s = json.loads(get("/stats"))
        for _ in range(4):
            if s["by_state"].get("dead", 0) == 1 and s.get("alive", 0) >= 3:
                break
            post("/check", {"scope": "all"})
            s = json.loads(get("/stats"))
        check("复检后健康 3 条", s.get("alive", 0) >= 3,
              f"alive={s.get('alive')} by_state={s['by_state']}")
        check("死代理不进入 alive", s["by_state"].get("dead", 0) == 1,
              f"by_state={s['by_state']}")

        m = get("/metrics")
        check("/metrics 暴露 Prometheus 计数",
              "proxy_gateway_conn_total" in m and "proxy_pool_alive" in m)

        alive = json.loads(get("/all?alive=1"))
        check("/all?alive=1 与 alive 计数一致", alive.get("count") == s.get("alive"),
              f"count={alive.get('count')} alive={s.get('alive')}")

        # ——— 5. 认证与 API token ———
        post("/add", {"proxies": ["http://127.0.0.1:19002"]})  # 去重，应 0 新增
        check("重复代理不重复入库",
              json.loads(get("/stats")).get("total") == 4,
              f"total={json.loads(get('/stats')).get('total')}")

    finally:
        for p in (proc, mock):
            p.terminate()
        try:
            out, _ = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        try:
            mock.wait(timeout=10)
        except subprocess.TimeoutExpired:
            mock.kill()
        print("\n--- poolsd 进程日志（尾部） ---")
        for line in (out or "").strip().splitlines()[-14:]:
            print("   ", line)
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(DB + suffix)
            except OSError:
                pass
        try:
            os.remove(CFG)
        except OSError:
            pass

    print()
    if fails:
        print(f"冒烟失败 {len(fails)} 项: {fails}")
        return 1
    print("端到端冒烟：全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())