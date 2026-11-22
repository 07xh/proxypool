# 通用代理池 · proxypool v1.0.0

零第三方依赖，纯 Python 标准库。一个常驻进程同时提供三样东西，宿主程序按需选一种接入：

| 接法 | 宿主需要改什么 | 适合 |
|---|---|---|
| **网关模式** | 为支持环境变量的客户端设置 `HTTP_PROXY`、`HTTPS_PROXY`；部分浏览器/Java 程序需另行配置 | curl / requests / Scrapy 等 HTTP 客户端 |
| **取用模式** | 每轮调一次 `/get` 拿 `host:port` | 需要自己控制换线时机、做粘性会话 |
| **回调上报** | 每次请求后 `POST /report` | 想让池子按真实业务成败（而非体检）调整权重 |

---

## 一、三分钟跑起来

```bash
cd proxypool

# 1. 把自己的代理写进 proxies.local.txt（一行一条，不跟踪到 Git）
#    1.2.3.4:8080
#    http://user:pass@1.2.3.4:8080
#    socks5://user:pass@1.2.3.4:1080

# 2. 起守护进程（体检 + 网关 + API 一起起）
python poolsd.py -c pool.json

# 3. 宿主程序只要一个环境变量就接管全部出网流量
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080

# 4. 随便跑你要跑的东西
curl -s http://example.com
```

代码里用：

```python
import requests
proxies = {"http": "http://127.0.0.1:18080", "https": "http://127.0.0.1:18080"}
requests.get("https://example.com", proxies=proxies, timeout=15)
```

网关每次连接自动从池里挑一条，失败自动换下一条重试（`max_retry` 控制），宿主完全无感。

---

## 二、文件清单

| 文件 | 作用 |
|---|---|
| `poolsd.py` | 全部核心：池调度 / 体检 / 网关 / API / SQLite 持久化 / 内置自测 |
| `poolclient.py` | 宿主侧接入库：取代理、上报、等池子热、网关环境变量上下文、失败换线重试器 |
| `pool.json` | 配置样例 |
| `proxies.txt` | 被跟踪的纯示例文件，**不能写真实代理或密码** |
| `proxies.local.txt` | 本机私有代理列表，默认实际数据源，不纳入 Git |
| `security_test.py` | TLS、请求重试、账号凭据和环境变量的离线安全回归 |
| `mock_upstream.py` | 测试用假世界：假目标站 / 假代理 A、B / 假死代理 / 假 SOCKS5 / TCP echo |
| `smoke.py` | 端到端冒烟：真实进程 + 真实端口 + 真实 socket 字节回读 |
| `auth_test.py` | 认证面验证：API token、网关 Basic、客户端库对接 |
| `verify.py` | 一键验收，`--fast` 只跑内置自测 |

---

## 三、HTTP API

默认 `http://127.0.0.1:18081`。推荐用 `PROXYPOOL_API_TOKEN` 提供 API Token，并使用 `Authorization: Bearer <token>`。仍保留 `?token=` 兼容形式，但 URL 可能被日志记录，**不建议传真实令牌**。带密码代理必须设置非空 API Token 才能通过 `/get` 取出或 `/add` 添加；`/all` 和代理详情默认脱敏。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/get` | 取一条代理，返回 JSON。参数 `strategy=`、`format=json\|text\|url\|env\|curl\|scrapy` |
| GET | `/get/{session}` | 同一 session 在 `sticky_ttl` 内粘同一条线（登录态、下单流程必须用这个） |
| GET | `/all` | 全量列表；`?alive=1` 只列健康 |
| GET | `/stats` | 池统计：总数/可用数/状态分布/P50 P90 延迟/会话数/累计成败 |
| GET | `/metrics` | Prometheus 文本格式，接 Grafana 直接用 |
| GET | `/health` | 存活探针 |
| POST | `/add` | `{"proxies":["1.2.3.4:8080","socks5://u:p@1.2.3.4:1080"]}`，自动去重 |
| POST | `/delete` | `{"ids":[1,2]}` |
| POST | `/report` | `{"id":1,"ok":true,"latency_ms":120}` 让池子学习真实成败 |
| POST | `/check` | `{"scope":"all"}` 或 `{"ids":[...]}` 立即触发体检 |
| POST | `/flush` | 把内存状态落盘 |
| GET | `/` | 浏览器打开看仪表盘 |

取一条的几种形态：

```bash
curl -s  http://127.0.0.1:18081/get?format=text      # 1.2.3.4:8080
curl -s  http://127.0.0.1:18081/get?format=url       # http://user:pass@1.2.3.4:8080
curl -s  http://127.0.0.1:18081/get?format=env       # 直接 export 的一段
curl -s  http://127.0.0.1:18081/get?format=curl      # -x http://...
curl -s 'http://127.0.0.1:18081/get?format=scrapy'   # Scrapy DOWNLOADER_MIDDLEWARES 用的 dict
```

---

## 四、调度与判死

### 状态机

```
new ──体检通过──> alive ──失败──> alive(降权)
 │                 │
 └──体检失败──> probation ──连续失败达 max_dead_retry──> dead ──退避到期──> 复检
```

- `new`：刚入库没体检过。`allow_cold_start=true` 时允许临时使用（急着开跑时有用）。
- `alive`：体检通过，正常供给。
- `probation`：体检失败但还没到判死阈值，仍可能被选中（给偶发抖动的代理机会）。
- `dead`：连续失败达阈值。按 `60s × 2^n` 退避，上限 30 分钟，到期自动复检复活。**不会永久拉黑**——免费代理本来就时好时坏。

### 四种策略（`pool.strategy`）

| 策略 | 行为 | 什么时候用 |
|---|---|---|
| `weighted_random`（默认） | 按 `0.55×成功率 + 0.30×延迟分 + 0.15×新鲜度` 加权随机 | 通用，兼顾质量和分散 |
| `round_robin` | 严格轮转 | 需要均匀压到每条线上，做限速规避 |
| `fastest` | 只看最快的 5 条里随机 | 延迟敏感（抢购、秒杀、实时接口） |
| `random` | 纯随机 | 不在乎质量，只要分散 |

### 粘性会话

```bash
curl 'http://127.0.0.1:18081/get/session-job-42'          # 同一 session 粘 300 秒
curl 'http://127.0.0.1:18081/get?session=job-42&strategy=fastest'
```

只要是「需要同一出口 IP 连续操作」的场景（登录 → 下单 → 验证），一律用 session 取，别用裸 `/get`。

---

## 五、体检：判「活得对不对」，不只判「连得上」

```json
"checker": {
  "interval": 120,
  "concurrency": 64,
  "timeout": 8.0,
  "targets": ["http://www.gstatic.com/generate_204", "http://httpbin.org/ip"],
  "expect_contains": ""
}
```

三道判据，缺一条都会把「假活代理」放进来：

1. **状态码 2xx/3xx**；
2. **状态 200 但响应体为空 → 判失败**（拦截页、认证跳转、肉鸡上的假代理，典型表现就是 200 + 空体）；
3. **`expect_contains` 非空时，响应体必须包含该串**。免费代理池最常见的坑是被运营商/中间盒劫持成广告页或验证页，它们回 200 且带内容。填一个目标站特征串（如 `"origin"`、`"\"ip\""`）就能过滤掉。

多个 `targets` 会轮换使用，避免单点被限速。`startup_sweep` 为 true 时启动先全量体检一遍再对外供线。

---

## 六、接入示例

### 6.1 requests：自动换线重试

```python
import requests
from poolclient import ProxyPoolClient, request_with_rotation

pc = ProxyPoolClient("http://127.0.0.1:18081")

def fetch(proxy_url, proxy_id):
    return requests.get("https://target.example/api", timeout=15,
                        proxies={"http": proxy_url, "https": proxy_url},
                        headers={"User-Agent": "Mozilla/5.0"})

r = request_with_rotation(fetch, pc, session="job-1", attempts=4)
print(r.status_code, len(r.content))
```

`request_with_rotation` 会在异常或 `429/500/502/503/504` 时换下一条线，并把真实成败 `POST /report` 回池子 —— 池子的权重会因为你的真实业务结果变准，比纯体检准得多。

### 6.2 Scrapy DOWNLOADER_MIDDLEWARES

```python
# middlewares.py
import random
from poolclient import ProxyPoolClient, NoProxyAvailable

class PoolProxyMiddleware:
    def __init__(self):
        self.pc = ProxyPoolClient("http://127.0.0.1:18081")

    def process_request(self, request, spider):
        try:
            p = self.pc.get(session=spider.name)
        except NoProxyAvailable:
            return None                      # 池空则直连
        request.meta["proxy"] = p["url"]
        request.meta["pool_id"] = p["id"]
        return None
```

```python
# settings.py
DOWNLOADER_MIDDLEWARES = {
    "myproj.middlewares.PoolProxyMiddleware": 543,
}
RETRY_HTTP_CODES = [429, 500, 502, 503, 504]
```

### 6.3 Selenium / Playwright（走网关最省事）

```python
from poolclient import GatewaySession
from selenium import webdriver

with GatewaySession("http://127.0.0.1:18080"):
    opts = webdriver.ChromeOptions()
    opts.add_argument("--proxy-server=http://127.0.0.1:18080")
    d = webdriver.Chrome(options=opts)
    d.get("https://example.com")
```

浏览器不认环境变量，必须显式 `--proxy-server` 指到网关。

### 6.4 通用命令行 / 任意语言

```bash
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
export NO_PROXY=127.0.0.1,localhost

python your_script.py
node your_script.js
go run main.go
```

任何遵守 `HTTP_PROXY` 的工具（Go / Node / Ruby / Java 的 `-Dhttp.proxyHost` 除外）都会被接管。

### 6.5 网关加了认证之后

```bash
export HTTP_PROXY=http://pooluser:poolpass@127.0.0.1:18080
export HTTPS_PROXY=$HTTP_PROXY
```

### 6.6 Java（不吃环境变量，必须显式传）

```bash
java -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=18080 \
     -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=18080 -jar app.jar
```

---

## 七、动态拉取代理源

```json
"sources": [
  {"type": "file", "name": "local", "path": "proxies.txt"},
  {"type": "url",  "name": "vendor-api", "url": "http://your-provider/api?count=200"}
]
```

- `file`：启动时读一次。
- `url`：启动时拉一次；返回体按行解析，同样支持四种写法。
- 两种源都走同一个去重逻辑，`scheme+host+port` 唯一。

想周期刷新，在调度器里作为 `--once` 加 cron：

```bash
# 每 10 分钟：拉新源 + 全量体检
*/10 * * * * cd /path/to/proxypool && python poolsd.py -c pool.json --once
```

`--once` 跑完体检、把状态落盘、退出，不占端口。

---

## 八、配置项全表

```json
{
  "api":     {"host": "127.0.0.1", "port": 18081, "token": ""},
  "gateway": {
    "enabled": true,
    "host": "127.0.0.1", "port": 18080,
    "auth": "",
    "max_retry": 2,
    "retry_on_status": [502, 503, 504],
    "direct_fallback": false,
    "connect_timeout": 15.0,
    "idle_timeout": 120.0
  },
  "checker": {
    "enabled": true, "interval": 120, "concurrency": 64, "timeout": 8.0,
    "targets": ["..."], "expect_contains": "",
    "startup_sweep": true, "max_bytes": 32768
  },
  "pool": {
    "strategy": "weighted_random",
    "sticky_ttl": 300,
    "allow_cold_start": true,
    "max_dead_retry": 3
  },
  "storage": {"db": "proxies.db", "flush_interval": 5, "persist_credentials": false},
  "sources": [],
  "log_level": "info"
}
```

| 键 | 说明 |
|---|---|
| `gateway.auth` | `"user:pass"`，让网关要求 Basic 认证。对外暴露端口时必填 |
| `gateway.max_retry` | 一个客户端请求最多换几条上游；`2` 表示最多试 3 条 |
| `gateway.retry_on_status` | 仅 GET、HEAD、OPTIONS 会按配置自动重试。POST/PATCH/PUT/DELETE 等写操作默认只发送一次，防止重复提交 |
| `gateway.direct_fallback` | 池空/全死时是否直连兜底。**做采集类任务建议 false**：直连兜底会拿你的真实 IP 出去 |
| `storage.persist_credentials` | 默认 `false`：新代理密码只保存在内存，不写入 SQLite；需要从本地私有代理源重新加载。兼容选项 `true` 会明文持久化，不推荐 |
| `pool.allow_cold_start` | 冷启动允许尝试尚未完成体检的代理 |
| `pool.max_dead_retry` | 连续失败几次判死。`3` 比较稳；代理质量差时调到 `2` 快速淘汰 |

环境变量也能覆盖，方便容器化：`PROXYPOOL_API_PORT`、`PROXYPOOL_GATEWAY_PORT`、`PROXYPOOL_API_TOKEN`、`PROXYPOOL_DB`。

命令行覆盖：`--port`、`--gateway-port`、`--token`、`--db`、`--strategy`、`--log-level`、`--import FILE`。

---

## 九、验收

```bash
python verify.py --fast    # 内置自测 + 离线安全回归
python verify.py           # 全套：内置自测 + 安全回归 + 端到端冒烟 + 认证面
```

内置自测（18 项）覆盖：入库去重、代理行解析、体检判活/判死、调度不返回死代理、粘性会话、HTTP 转发、`Proxy-Authorization` 剥离、API 各端点、SQLite 持久化、空池行为。

端到端冒烟覆盖：

- 守护进程以**独立子进程**启动（不是同进程调用），真实监听端口；
- 24 发 HTTP 请求全部 200，且 A、B 两条上游**都被轮换到**（证明调度生效）；
- **CONNECT 隧道**对真实 TCP 服务做字节级回读（`ECHO:tunnel-ping-42` 原样回来），HTTPS / WebSocket 走的就是这条；
- 池里混入死代理后，隧道仍然成功（证明自动换线）；
- `socks5://` 上游同样能承载隧道；
- Prometheus `/metrics` 有计数。

认证面覆盖：API 无 token 401 / 正确 200 / 错误 401 / `?token=` 放行；网关无凭据 407 / 正确 Basic 200 / 错误 407；`poolclient` 五套方法在真实进程上跑通。

---

## 十、已实测 / 未实测

**已实测**（本机 Python 3.15 / Windows，全部脚本 `verify.py` 一次跑绿）：

- 守护进程常驻、双端口监听、信号退出、状态落盘
- 代理入库去重、SQLite 重启后状态保留
- 体检：健康代理判 alive、死代理连续失败判 dead、退避复活
- 网关 HTTP 明文转发 + CONNECT 隧道 + 字节级回读
- 死代理自动换线重试、SOCKS5 上游承载隧道
- A/B 双上游轮换命中（24 发全部命中）
- API token、网关 Basic 认证、407/401 分支
- `/get` 六种 format、`/stats`、`/metrics`、`/all?alive=1`、`/add`、`/check`
- `poolclient` 全部方法

**未实测**（配置了代码路径，但不能据此保证真实上游兼容）：

- **HTTPS 目标经 HTTPS 代理（`https://` 上游 + TLS → TLS 双层）** —— 代码路径已实现（先对代理建 TLS，再 CONNECT 后 `start_tls` 到目标），本机没有真实 HTTPS 代理可打，未跑过真实握手。
- **`socks4` 上游** —— 解析器识别 `socks4://`，但握手只实现了 SOCKS5；实际使用 `socks4://` 会走 SOCKS5 握手并失败。要用 SOCKS4 先在 `open_tunnel` 里补 `_socks4_handshake`。
- **上游代理需要非 Basic 认证**（NTLM / Digest）—— 未实现，只支持 Basic 与 SOCKS5 用户名口令。
- **真实公网代理池的大规模压测** —— 并发上限、内存占用、SQLite 在几千条规模下的表现未测。

---

## 十一、故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 宿主程序仍然用直连 | 环境变量没进到子进程 | `NO_PROXY` 里别带目标域名；`curl -v` 看 `Connected to 127.0.0.1:18080` |
| 大量 502 `no healthy upstream proxy` | 池子没热或全死 | `curl /stats` 看 `alive`；`POST /check` 强制体检；看 `by_state` |
| `dead` 一直是大多数 | 代理源质量差 / 体检目标被墙 | 换 `targets` 为国内可达地址，调大 `timeout`，调小 `max_dead_retry` |
| 采到的是广告页/验证页 | 代理被劫持，200 + 有内容 | 配 `expect_contains` 校验目标特征串 |
| 登录态丢失 / 下单串号 | 用了裸 `/get` 而非 session | 改用 `/get/{session}`，`sticky_ttl` 调大 |
| Selenium 不走代理 | 浏览器不吃 HTTP_PROXY | 加 `--proxy-server=http://127.0.0.1:18080` |
| Java 程序不走代理 | JVM 不吃环境变量 | `-Dhttp.proxyHost` / `-Dhttps.proxyHost` |
| Windows 端口被占 | 18080/18081 冲突 | `--port` / `--gateway-port` 换端口 |

---

## 十二、设计取舍说明

**为什么用网关而不是只给 API**：绝大多数现成程序（curl、wget、任意 HTTP 库、浏览器）本身就支持「配一个代理」，但不支持「每请求轮换 + 失败换线」。网关把这个能力做成透明的一层，宿主零改造。API 模式留给需要精确控制换线时机的场景。两种共用同一个池子和同一套评分。

**为什么每个请求换一条线而不是固定一条**：固定一条线在代理挂掉时整批任务全废；每请求换线保证任何单点故障最多损失一条请求。

**为什么判死不永久拉黑**：免费代理池的存活是波动的，一条今天挂的线明天可能活。用指数退避（60s → 30min）做概率性复活，比永久黑名单的整体吞吐更高。

**为什么体检要查响应体**：只查 TCP 通不通或状态码会放进大量「能连但不干活」的代理（拦截页、认证墙、假代理）。空体判定 + 特征串判定这两道是免费池可用性的关键。

**为什么上报接口存在**：体检用的是固定探测目标，和你的真实业务目标不同。真实业务成败（你的 `/report`）比体检更能反映代理对**你的目标**好不好用，所以评分里 `ema_ok` 权重最高。**做重要任务时一定要接 report**，不然池子只是「连得上」，不是「打得通你的目标」。
## 十三、安全修订与兼容说明（2026-11-22）

- HTTPS 代理和 HTTPS 目标的证书与主机名现在采用 Python 系统信任链校验；自签/错误证书会被拒绝。普通 CONNECT 隧道本身仍是不解析目标 TLS 内容的透传。
- 网关不再重放 POST、PUT、PATCH、DELETE 等可能产生副作用的请求。`poolclient.request_with_rotation()` 未指明 `method` 时只尝试一次；需要对安全的读取请求重试时显式声明 `method="GET"` 等。
- 管理 API 代理列表和详情默认脱敏。对于需要用户名/密码的代理，必须配置 API Token；取得带认证代理的请求格式继续支持既有客户端。
- SQLite 对**新加入**的代理默认不写入用户名和密码，重启后需要加载 `proxies.local.txt` 补充内存中的认证信息。**旧数据库中的既有明文凭据不会被自动清除**，需单独备份和审核。`proxies.local.txt` 本身可能含明文，务必妥善保护本机文件权限。
- 原有 `proxies.txt` 保留为 Git 跟踪的格式样例。实际加载源由 `pool.json` 指向被忽略的 `proxies.local.txt`，没有实际代理时不会凭空生成可用公网代理。
- `GatewaySession` 退出时恢复原始 `NO_PROXY`、`no_proxy`、`PROXYPOOL_GATEWAY_AUTH`，以及四个 HTTP 代理环境变量。
- `security_test.py` 已加入 `verify.py` 的测试清单；仓库提交本身不代表 CI 或本机测试已执行。

## 十四、HTTP 报文边界修复

- 网关解析 `Transfer-Encoding: chunked` 请求后会重新生成 `Content-Length`，不再把去分块后的数据配上旧的分块头转发给上游。
- 同时存在 `Content-Length` 和 `Transfer-Encoding`、重复长度头、无效分块结构等请求将被拒绝（400）。过大的请求体会返回 413，而不是截断后发送错误长度。
- 网关请求体默认上限 8 MiB；管理 API 继续采用较小的 256 KiB 上限。健康检查读取的响应仍可按 `max_bytes` 截取，不把长响应错误当成请求超限。
- 新增 `framing_test.py` 离线测试并纳入 `verify.py`；未对真实上游进行联网测试。
## 十五、响应完整性与本地验收

- HTTP 健康检查支持无 `Content-Length`、无 `Transfer-Encoding`、通过连接关闭确定结束的有效响应，避免将此类代理误判为不可用。
- 网关读取上游响应若超时、连接异常或超过 64 MiB 缓冲上限，将返回错误，不再把不完整响应作为成功结果交给客户端。大文件与无限流式响应仍非当前缓冲实现的适用场景。
- 网关和管理 API 的请求体读取增加超时控制，无法发完请求体时返回 HTTP 408，避免连接一直等待。
- 新增 `response_test.py`，包含 6 项离线测试，并纳入 `verify.py`。
- Windows 可直接运行 `verify-local.cmd`，检查 Python 语法并执行完整本地测试。**这个入口并不代表测试已经在用户电脑执行。**
- 2026-11-22 首次 GitHub Actions 运行在 Windows、Ubuntu 两个平台均显示 0 毫秒、无步骤记录；这是工作流运行失败，但尚无证据证明由 Python 测试造成，不能标记为测试通过。
## 十六、HTTP 响应提前断连校验

- 完整收到 EOF 仍不一定表示成功：若上游声明了 `Content-Length`，但实际收到的正文长度不足或多出字节，网关会拒绝返回损坏响应。
- 对 `Transfer-Encoding: chunked` 响应检查分块大小、结束分块与尾部字段，拒绝不完整分块数据。
- 支持正常的 `100 Continue` 后续最终响应，以及 `HEAD`、`204` 等无需响应体的情况。
- 无明确消息长度的 HTTP 响应继续由连接 EOF 确定结束。仍采用最多 64 MiB 的缓冲模式；暂不支持大型文件/长连接流式转发。
- `response_test.py` 新增 8 项针对内容完整性的本地测试。GitHub Actions 执行仍需验证，不能因提交成功宣称测试通过。


## 十七、公开代理订阅与自动验证（本次新增）

保留现有 `sources`（本地文件、自有代理商 URL）和原有网关调度；新增独立的 `public_sources` 配置。示例 `pool.json` 已启用 monosans 的 HTTP/SOCKS5 两条公开列表（最多各 80 个候选，30 分钟刷新一次）；可将 `enabled` 改为 `false` 禁止联网收集。首次启动需要能访问 `raw.githubusercontent.com`。

- **安全边界**：公开源仅允许 HTTPS 的 `raw.githubusercontent.com` 文本列表，限制下载体积为 1 MiB；仅解析全球可路由的 IPv4 HTTP/SOCKS5 代理，拒绝内网/本机地址、携带认证信息的公开条目和 SOCKS4。
- **先验后用**：新导入的公开代理默认禁用，使用现有健康检查器验证后才启用。重启时已保存的公开代理先隔离，再次验证；来源失联时不把未验证的代理放入可用池。
- **去重和来源隔离**：继续使用 SQLite 的 `scheme+host+port` 唯一索引；同名代理来自其他合法来源时不会覆盖原来源或认证数据；既有手动来源不受影响。
- **后台刷新**：每条源独立刷新时间；默认 1800 秒，允许 300–86400 秒，最多每源 150 条；每次仅复核新导入和未通过认证的候选，已启用节点由原健康检查器周期复检。
- **管理 API**：`GET /sources` 查看各源最近刷新时间、解析数、入库数、已验证数与错误；`POST /sources/refresh` 手动拉取全部源，或 POST JSON `{"name":"monosans-http"}` 只刷新指定来源。仍受原 API Token 保护。
- **离线验证**：新增 `public_sources_test.py`，检查非法地址过滤、去重、健康通过启用、失败隔离、重启重新验证和刷新周期，不依赖公网访问。

注意：公开代理 IP 是不可信的第三方计算机，列表来源可信不代表代理本身可信；不要通过它们访问校园账号、金融账户或发送任何个人信息。某些 HTTPS 目标和 WebSocket/流式场景可能仍受现有网关限制。

若机器无法访问 GitHub Raw，源状态会报告下载错误，但本地手动代理来源与其他核心功能保持可用。运行 `python verify.py` 验证离线功能；本次提交不表示 CI 已经成功，也不代表现有公网代理一定可用。


## 十八、现有代理池整合优化（重试、会话与桌面启动）

本项目现已独立发布在 `07xh/proxypool`，保留原代理池网关、调度、客户端、公开来源与桌面管理功能。

- **不再反复选中同一个失败节点**：网关 GET/HEAD/OPTIONS 和 CONNECT 在单个请求的重试期间排除已经尝试过的代理，耗尽不同候选后明确失败。非幂等请求仍不自动重放。
- **粘性会话可控失效**：`POST /sessions/invalidate` 接受 `{"session":"job","proxy_id":123}`，仅当当前绑定仍指向该 ID 时解除绑定；`GET /get?exclude=1,2` 可排除本轮已失败代理。客户端库增加 `invalidate_session()`。
- **客户端库不再回环**：管理 API 请求强制直连回环地址，不受 `HTTP_PROXY` 环境变量影响。自动重试器必须明确传入 `method="GET"`，否则最多尝试一次。HTTP 429 不进行换线重试，应遵守服务端频率要求。
- **指标与 UI 一致**：`/stats.alive` 只计数已启用且健康的代理；`/sources` 增加 `in_pool`、`available_now`、`quarantined` 实时数量，桌面 UI 不再用上次检测通过数代替当前可用数。
- **一键打开**：Windows 桌面 GUI 启动后自动尝试启动已有本地服务；已有实例占用端口时显示错误，不重复启动。
- **离线测试**：`rotation_test.py` 通过模拟代理和本地 SDK 校验排除、粘性会话、禁用节点统计、客户端方法与 HTTP 429 不自动重试。运行 `python verify.py`。

**说明**：上述是代码改动及测试用例，不代表公网代理或 Windows EXE 已通过实际运行验收。

## 十九、CDN 直连节点（与代理池隔离）

这是独立的**目标站直连 TLS 端点目录**，不能作为 HTTP/SOCKS5 代理使用，也不会进入 `/get`、`/all`、代理健康检查、网关或自动轮换流程。

- **原通用代理池**：`proxies.local.txt`，由原有接口和网关管理。
- **目标直连节点**：`direct_nodes.local.txt`，格式为 `ip,port,sni,latency_ms,response_bytes`，本机保存且已加入 `.gitignore`。
- Windows 桌面管理界面新增 **CDN 直连节点** 页和 **导入直连节点** 按钮，可以直接选择本机已有的 `cdn_nodes.txt`（或相同结构的 JSON）；不会把节点改写成代理。
- 只接收 `pool.json` 的 `direct_nodes.allowed_hosts` 明确允许的 SNI，默认 `kyfw.12306.cn`。其他目标须明确修改允许列表。
- 来源是用户**本地导入的历史实测记录**。导入不会重新联网测活；`fresh` 只表示数据时间在 72 小时之内，**不代表此刻节点健康**。
- JSON 如含 `generated` 则按采集时间判断新鲜度；TXT 按源文件修改时间判断（桌面导入时保留原时间）。超时仍能查看记录，但 `/direct/get` 返回 503。

示例查询（守护进程运行后）：

```bash
curl http://127.0.0.1:18081/direct/stats
curl http://127.0.0.1:18081/direct/all
curl 'http://127.0.0.1:18081/direct/get?host=kyfw.12306.cn'
curl -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:18081/direct/reload
```

或者：

```python
from poolclient import ProxyPoolClient
client = ProxyPoolClient()
print(client.direct_stats())
node = client.direct_get("kyfw.12306.cn")
# node == {"type": "direct_tls", "ip": "...", "port": 443,
#          "sni": "kyfw.12306.cn", "latency_ms": ..., "response_bytes": ...,
#          "is_proxy": False}
# 不要传入 requests 的 proxies 参数。
```

未随仓库提交用户的 171 条节点记录及本地采集脚本；本仓库无法访问用户 Windows 上的绝对路径。现阶段实现**导入、隔离、目录/API 取用和新鲜度检查**，未实现自动 ECS 采集、定期在线测活、目标业务的请求发送或 ticket 业务逻辑。需要对 TLS 端点发起合法请求的宿主程序，应按 SNI 域名严格校验证书，**不得使用** `CERT_NONE`、`verify=False`；同时遵守目标网站的使用规则。stunnel 本身不提供 SOCKS5 代理协议。

离线测试：`python direct_nodes_test.py`，也已纳入 `python verify.py` 和 CI。
