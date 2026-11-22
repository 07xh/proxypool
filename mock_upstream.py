#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_upstream.py — 冒烟/隧道测试用的假世界（独立进程，模拟真实上游）

服务的端口：
  :19001  假目标站（JSON，回显收到的方法/路径/头和来源标记）
  :19002  假代理 A —— 支持 absolute-form GET + CONNECT 隧道，转发时打 X-Proxy-A
  :19003  假代理 B —— 同上，打 X-Proxy-B
  :19004  假死代理 —— 接了不转发直接断，验证换线重试
  :19005  假 SOCKS5（无认证）—— 验证 socks5:// 上游
  :19006  TCP echo —— 给 CONNECT 隧道做字节级回读断言

单独运行：python mock_upstream.py
"""
import asyncio
import json
import struct
import sys
from urllib.parse import urlsplit

CHUNK = 65536


async def read_head(reader):
    data = await reader.readuntil(b"\r\n\r\n")
    lines = data.decode("latin-1").split("\r\n")
    headers = []
    for ln in lines[1:]:
        if ln:
            k, _, v = ln.partition(":")
            headers.append((k.strip(), v.strip()))
    return lines[0], headers


def resp(status, headers, body=b""):
    line = {200: "200 OK", 400: "400 Bad Request", 403: "403 Forbidden",
            502: "502 Bad Gateway"}.get(status, f"{status} X")
    lines = [f"HTTP/1.1 {line}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if not any(k.lower() == "content-length" for k, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


async def origin(reader, writer):
    try:
        first, headers = await read_head(reader)
    except Exception:
        writer.close()
        return
    payload = json.dumps({
        "origin": "target-site",
        "request": first,
        "headers": {k.lower(): v for k, v in headers},
    }).encode()
    writer.write(resp(200, [("Content-Type", "application/json"),
                            ("Connection", "close")], payload))
    try:
        await writer.drain()
        writer.close()
    except Exception:
        pass


async def echo(reader, writer):
    try:
        while True:
            d = await reader.read(CHUNK)
            if not d:
                break
            writer.write(b"ECHO:" + d)
            await writer.drain()
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass


async def pipe(r, w):
    try:
        while True:
            d = await r.read(CHUNK)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


def make_proxy(tag):
    async def handler(reader, writer):
        try:
            first, headers = await read_head(reader)
        except Exception:
            writer.close()
            return
        parts = first.split()
        if len(parts) < 2:
            writer.close()
            return
        method = parts[0].upper()

        if method == "CONNECT":
            host, _, port_s = parts[1].partition(":")
            try:
                port = int(port_s or "443")
            except ValueError:
                writer.write(resp(400, [("Connection", "close")], b"bad port"))
                await writer.drain()
                writer.close()
                return
            try:
                ur, uw = await asyncio.open_connection(host, port)
            except Exception:
                writer.write(resp(502, [("Connection", "close")], b"connect fail"))
                try:
                    await writer.drain()
                    writer.close()
                except Exception:
                    pass
                return
            writer.write(f"HTTP/1.1 200 Connection Established\r\n"
                         f"X-Proxy-CONNECT-{tag}: 1\r\n\r\n".encode())
            await writer.drain()
            await asyncio.gather(pipe(reader, uw), pipe(ur, writer),
                                 return_exceptions=True)
            return

        target = parts[1]
        u = urlsplit(target)
        if not u.hostname:
            writer.write(resp(400, [("Connection", "close")], b"bad uri"))
            await writer.drain()
            writer.close()
            return
        try:
            r, w = await asyncio.open_connection(u.hostname, u.port or 80)
        except Exception:
            writer.write(resp(502, [("Connection", "close")], b"upstream fail"))
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass
            return
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        lines = [f"{method} {path} HTTP/1.1", f"Host: {u.netloc}", f"X-Proxy-{tag}: 1"]
        for k, v in headers:
            if k.lower() in ("host", "proxy-connection", "proxy-authorization", "connection"):
                continue
            lines.append(f"{k}: {v}")
        lines.append("Connection: close")
        w.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        try:
            await w.drain()
            await pipe(r, writer)
        except Exception:
            pass
        try:
            w.close()
        except Exception:
            pass
    return handler


async def dead_proxy(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass


async def socks5(reader, writer, tag="S5"):
    """最小 SOCKS5 服务端：无认证 + CONNECT。"""
    try:
        ver, nm = await reader.readexactly(2)
        methods = await reader.readexactly(nm)
        if ver != 0x05 or 0x00 not in methods:
            writer.close()
            return
        writer.write(b"\x05\x00")
        await writer.drain()
        head = await reader.readexactly(4)
        if head[1] != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        atyp = head[3]
        if atyp == 0x01:
            raw = await reader.readexactly(4)
            host = ".".join(str(b) for b in raw)
        elif atyp == 0x03:
            n = await reader.readexactly(1)
            host = (await reader.readexactly(n[0])).decode()
        else:
            writer.close()
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        try:
            ur, uw = await asyncio.open_connection(host, port)
        except Exception:
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        await asyncio.gather(pipe(reader, uw), pipe(ur, writer),
                             return_exceptions=True)
    except Exception:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    specs = [
        (origin, 19001, "target  JSON"),
        (make_proxy("A"), 19002, "proxyA  HTTP+CONNECT"),
        (make_proxy("B"), 19003, "proxyB  HTTP+CONNECT"),
        (dead_proxy, 19004, "dead    refuse"),
        (socks5, 19005, "socks5  无认证"),
        (echo, 19006, "echo    TCP"),
    ]
    servers = []
    for fn, port, name in specs:
        srv = await asyncio.start_server(fn, "127.0.0.1", port)
        servers.append(srv)
        print(f"up {name:22s} :{port}", flush=True)
    print("READY", flush=True)
    await asyncio.gather(*[s.serve_forever() for s in servers])


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)