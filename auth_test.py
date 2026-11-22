#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth_test.py — 认证面验证（API token + 网关 Basic 认证 + 客户端库对接）

断言：
  1. API 未带 token -> 401
  2. API 带正确 Bearer -> 200
  3. API 带错误 Bearer -> 401
  4. API 用 ?token= 查询串 -> 200（给不方便加头的宿主）
  5. 网关未带代理凭据 -> 407 且回 Proxy-Authenticate 头
  6. 网关带正确 Basic -> 隧道建立 200
  7. 网关带错误 Basic -> 407
  8. poolclient 库能 get_url / stats / report / add / delete
"""
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
API = "http://127.0.0.1:19091"
GATEWAY = ("127.0.0.1", 19090)
TOKEN = "s3cret-token"
DB = os.path.join(HERE, ".auth.db")
CFG = os.path.join(HERE, ".auth.json")


def wait_port(host, port, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def api_call(path, headers=None, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(API + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def gw_tunnel(auth_header=None):
    s = socket.create_connection(GATEWAY, timeout=10)
    lines = ["CONNECT 127.0.0.1:19006 HTTP/1.1", "Host: 127.0.0.1:19006"]
    if auth_header:
        lines.append(f"Proxy-Authorization: {auth_header}")
    lines.append("")
    lines.append("")
    s.sendall("\r\n".join(lines).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    head = buf.split(b"\r\n\r\n")[0].decode("latin-1")
    status = int(head.split()[1]) if len(head.split()) > 1 else 0
    s.close()
    return status, head


def main():
    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_upstream.py")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port("127.0.0.1", 19002):
        mock.terminate()
        print("mock upstream 起不来")
        return 2

    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(DB + suffix)
        except OSError:
            pass
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump({
            "api": {"port": 19091, "token": TOKEN},
            "gateway": {"enabled": True, "port": 19090, "auth": "pooluser:poolpass",
                        "max_retry": 1, "connect_timeout": 5.0, "idle_timeout": 30.0},
            "checker": {"enabled": False, "interval": 0, "startup_sweep": False,
                        "timeout": 4.0,
                        "targets": ["http://127.0.0.1:19001/echo"]},
            "pool": {"strategy": "weighted_random", "sticky_ttl": 60,
                     "allow_cold_start": True, "max_dead_retry": 2},
            "storage": {"db": DB, "flush_interval": 2},
            "sources": [],
            "log_level": "warn",
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
        for _ in range(80):
            if wait_port("127.0.0.1", 19091, 0.5):
                break
            time.sleep(0.3)

        st, _ = api_call("/stats")
        check("API 无 token -> 401", st == 401, f"status={st}")

        st, body = api_call("/stats", {"Authorization": f"Bearer {TOKEN}"})
        check("API 正确 Bearer -> 200", st == 200, f"status={st}")

        st, _ = api_call("/stats", {"Authorization": "Bearer wrong-token"})
        check("API 错误 Bearer -> 401", st == 401, f"status={st}")

        st, _ = api_call(f"/stats?token={TOKEN}")
        check("API ?token= 查询串放行", st == 200, f"status={st}")

        # 灌代理
        st, body = api_call("/add", {"Authorization": f"Bearer {TOKEN}"}, "POST",
                            {"proxies": ["http://127.0.0.1:19002"]})
        check("带 token 写入代理", st == 200 and json.loads(body)["added"] == 1, body)
        api_call("/check", {"Authorization": f"Bearer {TOKEN}"}, "POST", {"scope": "all"})

        # 网关认证
        st, head = gw_tunnel(None)
        check("网关无凭据 -> 407", st == 407, f"status={st}")
        check("407 回 Proxy-Authenticate 头", "proxy-authenticate" in head.lower(),
              head.replace("\r\n", " | ")[:120])

        good = "Basic " + base64.b64encode(b"pooluser:poolpass").decode()
        st, head = gw_tunnel(good)
        check("网关正确 Basic -> 200 隧道建立", st == 200, f"status={st}")

        bad = "Basic " + base64.b64encode(b"pooluser:nope").decode()
        st, head = gw_tunnel(bad)
        check("网关错误 Basic -> 407", st == 407, f"status={st}")

        # 客户端库
        import poolclient
        pc = poolclient.ProxyPoolClient(API, token=TOKEN)
        s = pc.stats()
        check("poolclient.stats() 可用", s.get("total") == 1, json.dumps(s.get("by_state")))
        pc.check()
        url = pc.get_url(session="job-7")
        check("poolclient.get_url() 返回可用地址",
              url.startswith("http://127.0.0.1:19002"), url)
        proxies = pc.get_requests_proxies()
        check("poolclient.get_requests_proxies() 返回 requests 可直用字典",
              set(proxies) == {"http", "https"} and proxies["http"] == proxies["https"])
        pid = pc.get()["id"]
        r = pc.report(pid, True, 88.0)
        check("poolclient.report() 上报成功", r.get("ok") is True, json.dumps(r))
        alive = pc.alive()
        check("poolclient.alive() 列健康代理", len(alive) == 1, f"n={len(alive)}")

        # 无 token 的客户端应报 401
        pc_bad = poolclient.ProxyPoolClient(API, token="")
        try:
            pc_bad.stats()
            check("无 token 的客户端被拒", False, "居然成功了")
        except urllib.error.HTTPError as e:
            check("无 token 的客户端被拒", e.code == 401, f"code={e.code}")

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
        print("\n--- poolsd 日志（尾部） ---")
        for line in (out or "").strip().splitlines()[-8:]:
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
        print(f"认证面失败 {len(fails)} 项: {fails}")
        return 1
    print("认证面 + 客户端库：全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())