#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify.py — 一键验收（三套测试串起来跑，退出码 0 表示全绿）

    python verify.py            # 全套
    python verify.py --fast     # 只跑内置自测（不占端口、不起子进程）
"""
import os
import subprocess
import sys

# Some Windows CI terminals default to cp1252 and cannot print Chinese text.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))


def run(name, script, args=None):
    print("\n" + "=" * 66)
    print(f"  {name}")
    print("=" * 66)
    cmd = [sys.executable, os.path.join(HERE, script)] + (args or [])
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    r = subprocess.run(cmd, cwd=HERE, env=env)
    ok = r.returncode == 0
    print(f"  -> {name}: {'OK' if ok else 'FAILED'} (exit={r.returncode})")
    return ok


def main():
    fast = "--fast" in sys.argv
    results = []
    results.append(("内置自测（组件级）", run("内置自测", "poolsd.py", ["--selftest"])))
    results.append(("安全回归（离线）", run("安全回归", "security_test.py")))
    results.append(("HTTP 报文边界测试", run("报文边界", "framing_test.py")))
    results.append(("响应完整性与超时测试", run("响应与超时", "response_test.py")))
    results.append(("公开来源离线回归", run("公开来源", "public_sources_test.py")))
    results.append(("调度会话与客户端回归", run("调度会话", "rotation_test.py")))
    if not fast:
        results.append(("端到端冒烟（真实进程/端口）", run("端到端冒烟", "smoke.py")))
        results.append(("认证面 + 客户端库", run("认证面", "auth_test.py")))

    print("\n" + "=" * 66)
    print("  验收汇总")
    print("=" * 66)
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    all_ok = all(ok for _, ok in results)
    print()
    print("结果:", "全部通过" if all_ok else "有失败项")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())