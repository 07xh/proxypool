# ProxyPool Manager（Windows 桌面第一版）

本仓库为独立公开项目 `07xh/proxypool`，保留原始 `poolsd.py`、SQLite、HTTP API、网关、健康检查和公开代理来源；增加一个标准库 tkinter 桌面工作台。

## 已实现
- 启动/停止本地代理池服务，退出时请求正常保存；
- 查看本地代理总数、可用数、P50 延迟与累计成功；
- 区分代理条目和独立公网 IPv4，展示近 5 分钟内最近成功确认的不同 IP 数量；
- 代理列表内可导入普通 HTTP / HTTPS / SOCKS5 TXT 清单，追加保存至本地私有文件并通过 /add 入库；与 CDN 导入严格隔离；
- 查看代理列表（地址、协议、延迟、健康状态、来源）和公开来源统计；
- 手动触发 `/sources/refresh`、`/check`；
- 使用后台线程读取 API，避免刷新界面时卡顿；
- 配置和数据默认放在 `%LOCALAPPDATA%\ProxyPoolManager`，初次运行自动复制仓库 `pool.json`；
- 仍仅用内置 `poolsd.App`，不引入 Redis 或另一套调度内核。

## 开发运行

在当前目录执行 `python manager_gui.py`。运行前需要可用的 Python tkinter。启动后点 **启动服务**，公开代理会在后台自动拉取和检测。

## Windows EXE

双击 `build_windows.cmd`（需要安装 Python 和 PyInstaller；脚本会尝试安装 PyInstaller），生成 `dist\ProxyPoolManager.exe`。用户运行**生成的 EXE** 不需要再安装 Python。

此仓库的 GitHub Actions 曾在执行步骤开始前失败，因此不能以新建构建工作流代替真实验证。必须在 Windows 机器实测生成的 EXE 后再发布 Release。不要把测试阶段的 EXE 当作已验收发布版。

## 使用范围与安全

默认 HTTP 网关端口 18080、管理 API 端口 18081。公开代理是第三方不可信节点，不要传输任何登录凭据、密码、金融、医疗、个人数据。该桌面界面不负责保证代理列表的真实性、合规性或稳定性。

如果端口已被其他服务占用，不能重复启动另一个实例；可以先关闭原服务。界面显示的可用数字来自本机 API，不是项目作者的测试值。

## CDN 直连节点（独立页面）

界面新增「CDN 直连节点」分页及「导入直连节点」按钮。本地选取 `cdn_nodes.txt`／CSV／JSON 后，会验证 IP、SNI、字段与重复项，将原始导出存入应用数据目录 `direct_nodes.local.txt`，并通过 `POST /direct/reload` 更新列表。原始文件时间保留，用于判定 72 小时新鲜度。页面可查看 IP、端口、SNI、历史耗时和响应字节。

该列表不是公共代理、不被通用网关使用。当前不在启动时自动发现 12306 CDN，也不重新检测活性；历史实测数量不等于实时可用数量。项目不包含或发布用户的节点文件。
