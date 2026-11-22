#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows-friendly desktop console for the existing standard-library proxy pool."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import queue
import shutil
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import urllib.request

import poolsd
from direct_nodes import parse_nodes


def data_dir() -> Path:
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        root = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(root) / "ProxyPoolManager"


def prepare_config(home: Path) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    config = home / "pool.json"
    if not config.exists():
        source_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
        sample = source_dir / "pool.json"
        if sample.is_file():
            shutil.copyfile(sample, config)
        else:
            config.write_text(json.dumps(poolsd.DEFAULT_CONFIG, indent=2), encoding="utf-8")
    return config


class Manager:
    def __init__(self):
        self.home = data_dir()
        self.config_path = prepare_config(self.home)
        self.config = poolsd.load_config(str(self.config_path))
        self.api_port = int(self.config["api"]["port"])
        self.token = str(self.config["api"].get("token") or "")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.events = queue.Queue()
        self.server_thread = None
        self.loop = None
        self.stop_event = None
        self.polling = False
        self.closing = False
        self.root = tk.Tk()
        self.root.title("ProxyPool Manager")
        self.root.geometry("1040x680")
        self.root.minsize(820, 520)
        self.build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self.read_events)
        self.root.after(700, self.poll)
        # One-click launch: automatically start the embedded service.
        self.root.after(350, self.start)

    def build_ui(self):
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)
        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="通用代理池", font=("Segoe UI", 14, "bold")).pack(side="left", padx=(0, 16))
        for text, action in (
            ("启动服务", self.start),
            ("停止服务", self.stop),
            ("刷新公开来源", lambda: self.post("/sources/refresh", {})),
            ("导入直连节点", self.import_nodes),
            ("重新检测", lambda: self.post("/check", {"scope": "all"}, 180)),
            ("刷新显示", lambda: self.poll(True)),
        ):
            ttk.Button(bar, text=text, command=action).pack(side="left", padx=3)
        frame = ttk.LabelFrame(outer, text="运行概览", padding=10)
        frame.pack(fill="x", pady=(0, 9))
        self.summary = tk.StringVar(value="本地服务尚未连接")
        ttk.Label(frame, textvariable=self.summary, font=("Segoe UI", 11)).pack(anchor="w")
        ports = self.config["gateway"]["port"], self.api_port
        ttk.Label(frame, text=f"网关：127.0.0.1:{ports[0]}     管理 API：127.0.0.1:{ports[1]}").pack(anchor="w", pady=(5, 0))
        tabs = ttk.Notebook(outer)
        tabs.pack(fill="both", expand=True)
        proxy_tab = ttk.Frame(tabs, padding=6)
        source_tab = ttk.Frame(tabs, padding=6)
        direct_tab = ttk.Frame(tabs, padding=6)
        tabs.add(proxy_tab, text="代理列表")
        tabs.add(source_tab, text="公开来源")
        tabs.add(direct_tab, text="CDN 直连节点")
        self.proxy_table = self.create_table(proxy_tab,
            ["编号", "协议", "地址", "端口", "状态", "延迟(ms)", "来源", "评分"],
            [65, 85, 160, 70, 85, 100, 210, 80])
        self.source_table = self.create_table(source_tab,
            ["来源", "协议", "启用", "读取数", "新增", "检测", "当前可用", "错误"],
            [165, 90, 65, 90, 70, 75, 75, 300])
        self.direct_summary = tk.StringVar(value="尚未导入直连节点")
        ttk.Label(direct_tab, textvariable=self.direct_summary).pack(fill="x", pady=(0, 7))
        self.direct_table = self.create_table(direct_tab,
            ["IP", "端口", "SNI 域名", "记录延迟(ms)", "响应字节", "类型"],
            [170, 75, 260, 135, 125, 125])
        ttk.Label(outer, text="注意：公开代理是不可信的第三方服务，不要用于登录账号或传输个人信息。",
                  foreground="#96641b").pack(anchor="w", pady=(8, 3))
        self.status = tk.StringVar(value=f"配置及数据库目录：{self.home}")
        ttk.Label(outer, textvariable=self.status, anchor="w").pack(fill="x")

    @staticmethod
    def create_table(parent, columns, widths):
        box = ttk.Frame(parent)
        box.pack(fill="both", expand=True)
        table = ttk.Treeview(box, columns=columns, show="headings")
        for name, width in zip(columns, widths):
            table.heading(name, text=name)
            table.column(name, width=width, minwidth=55, stretch=name in ("地址", "来源", "错误"))
        sb = ttk.Scrollbar(box, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=sb.set)
        table.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return table

    def api(self, endpoint, payload=None, timeout=8):
        url = f"http://127.0.0.1:{self.api_port}{endpoint}"
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
        with self.opener.open(req, timeout=timeout) as response:
            return json.load(response)

    def import_nodes(self):
        """Import the user's local TXT/CSV/JSON observations without mixing proxies."""
        source = filedialog.askopenfilename(
            title="选择 CDN 节点清单（非代理文件）",
            filetypes=[("节点清单", "*.txt *.csv *.json"), ("所有文件", "*.*")])
        if not source:
            return
        try:
            src = Path(source)
            if src.stat().st_size > 2_000_000:
                raise ValueError("文件不能超过 2 MB")
            content = src.read_text(encoding="utf-8-sig")
            allowed = self.config.get("direct_nodes", {}).get("allowed_hosts", ["kyfw.12306.cn"])
            nodes, counts = parse_nodes(content, allowed)
            if not nodes:
                raise ValueError("没有符合允许域名的节点；请确认 CSV 包含 ip,port,sni,延迟,字节")
            if counts["invalid"] and not messagebox.askyesno(
                "部分记录无效",
                f"将导入 {len(nodes)} 条节点，跳过 {counts['invalid']} 条不合规记录。继续？"):
                return
            configured = Path(self.config.get("direct_nodes", {}).get("path", "direct_nodes.local.txt"))
            target = configured if configured.is_absolute() else self.home / configured
            target = target.resolve()
            if target.parent != self.home.resolve():
                raise ValueError("清单必须保存到应用本地数据目录")
            tmp = target.with_name(target.name + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            stat = src.stat()
            os.utime(tmp, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            tmp.replace(target)
            self.post("/direct/reload", {})
            self.status.set(f"已导入 {len(nodes)} 条直连节点记录；这是历史测量，不代表实时可用")
        except (OSError, ValueError, UnicodeError) as exc:
            messagebox.showerror("导入失败", str(exc))

    def start(self):
        if self.closing:
            return
        if self.server_thread and self.server_thread.is_alive():
            self.status.set("服务已在本窗口运行")
            return
        self.status.set("正在启动，请查看运行概览……")
        self.server_thread = threading.Thread(target=self.run_backend, daemon=True)
        self.server_thread.start()

    def run_backend(self):
        async def serve():
            os.chdir(self.home)
            config = poolsd.load_config(str(self.config_path))
            self.loop = asyncio.get_running_loop()
            self.stop_event = asyncio.Event()
            app = poolsd.App(config)
            try:
                await app.start()
                self.events.put(("status", "代理池正在运行，公开来源在后台获取和检测"))
                await self.stop_event.wait()
            finally:
                await app.stop()
        try:
            asyncio.run(serve())
        except Exception as exc:
            self.events.put(("status", f"启动失败：{type(exc).__name__}: {exc}"))
        else:
            self.events.put(("status", "服务已停止，状态已保存"))
        finally:
            self.loop = None
            self.stop_event = None

    def stop(self):
        loop, event = self.loop, self.stop_event
        if loop is not None and event is not None and loop.is_running():
            loop.call_soon_threadsafe(event.set)
            self.status.set("正在停止并保存数据……")
        elif not self.closing:
            self.status.set("当前窗口没有运行中的服务")

    def post(self, endpoint, payload, timeout=60):
        self.status.set(f"正在执行 {endpoint} ……")
        def work():
            try:
                result = self.api(endpoint, payload, timeout)
                self.events.put(("status", f"已执行 {endpoint}: {json.dumps(result, ensure_ascii=False)[:130]}"))
                self.events.put(("repoll", True))
            except Exception as exc:
                self.events.put(("status", f"操作失败：{type(exc).__name__}: {exc}"))
        threading.Thread(target=work, daemon=True).start()

    def poll(self, force=False):
        if self.closing:
            return
        if not self.polling:
            self.polling = True
            threading.Thread(target=self.read_snapshot, daemon=True).start()
        if not force:
            self.root.after(4000, self.poll)

    def read_snapshot(self):
        try:
            stats = self.api("/stats", timeout=5)
            proxies = self.api("/all", timeout=6).get("proxies", [])
            sources = self.api("/sources", timeout=5).get("sources", [])
            direct_stats = self.api("/direct/stats", timeout=5)
            direct_nodes = self.api("/direct/all", timeout=5).get("nodes", [])
            self.events.put(("snapshot", (stats, proxies, sources, direct_stats, direct_nodes)))
        except Exception:
            self.events.put(("offline", True))
        finally:
            self.events.put(("polled", True))

    @staticmethod
    def fill(table, rows):
        for iid in table.get_children():
            table.delete(iid)
        for row in rows:
            table.insert("", "end", values=row)

    def read_events(self):
        try:
            while True:
                event, value = self.events.get_nowait()
                if event == "snapshot":
                    stats, proxies, sources, direct_stats, direct_nodes = value
                    self.summary.set(
                        f"代理 {stats.get('total', 0)}   可用 {stats.get('alive', 0)}   "
                        f"P50 {stats.get('latency_p50_ms', 0)} ms   "
                        f"累计成功 {stats.get('total_success', 0)}")
                    self.fill(self.proxy_table, [
                        (p.get("id"), p.get("scheme"), p.get("host"), p.get("port"),
                         p.get("state"), p.get("latency_ms"), p.get("source"), p.get("score"))
                        for p in proxies[:1000]])
                    self.fill(self.source_table, [
                        (s.get("name"), s.get("scheme"), "是" if s.get("enabled") else "否",
                         s.get("listed"), s.get("added"), s.get("checked"),
                         s.get("available_now"), s.get("error") or "")
                        for s in sources])
                    self.direct_summary.set(
                        f"历史节点 {direct_stats.get('total', 0)}  "
                        f"新鲜度 {'未过期' if direct_stats.get('fresh') else '已过期/未导入'}  "
                        f"采集时间 {direct_stats.get('generated_at') or '未知'}  "
                        f"实时检测：未执行（{direct_stats.get('error') or '无错误'}）")
                    self.fill(self.direct_table, [
                        (n.get("ip"), n.get("port"), n.get("sni"), n.get("latency_ms"),
                         n.get("response_bytes"), "直连 TLS（非代理）")
                        for n in direct_nodes[:1000]])
                elif event == "offline":
                    self.summary.set("本地 API 尚未连接")
                elif event == "polled":
                    self.polling = False
                elif event == "status":
                    self.status.set(str(value))
                elif event == "repoll":
                    self.poll(force=True)
        except queue.Empty:
            pass
        if not self.closing:
            self.root.after(150, self.read_events)

    def close(self):
        self.closing = True
        self.stop()
        self.root.after(1200, self.root.destroy)


def main():
    home = data_dir()
    home.mkdir(parents=True, exist_ok=True)
    if getattr(sys, "frozen", False) and sys.stdout is None:
        logfile = open(home / "manager.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = logfile
        sys.stderr = logfile
    try:
        Manager().root.mainloop()
    except Exception as exc:
        messagebox.showerror("ProxyPool Manager", f"无法启动：{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    main()
