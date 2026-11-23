# 07xh/proxypool · 隐蔽性工程审计与改造报告

对象：`07xh/proxypool` @ `main`（commit `06c12f3`，2026-11-22T14:43:04Z push，Python 1.0.0，零第三方依赖）
本地副本：`proxypool-opt/`；上游原样副本：`proxypool-opt/_upstream/poolsd.py`（90 363 字节，未改动，用于对拍）
改造范围：新增 `poolopt.py`（37 672 B）+ 改 `poolsd.py` / `poolclient.py` / `pool.json` / `rotation_test.py` / `security_test.py` + 新增 `hardening_test.py`

---

## 一、先说结论

这个仓库的工程质量在同类里属于上游：报文边界严格（`framing_test` / `response_test` 共 21 项）、非幂等请求不重放、凭据默认不落 SQLite、状态机与退避有完整实现。**它的问题不在工程正确性，在隐蔽性——它把「代理池」做成了「能连上的 IP 集合」，下面三层一条都没过：**

| 层 | 目标侧看到什么 | 本仓库原状 |
| --- | --- | --- |
| 连接干净 | 转发头、UA 改写、注入页 | 部分防（`expect_contains` + 空体判定），但**无转发头检测**、**无注入探针**、**无内容比对** |
| 身份不关联 | TLS 指纹、头序、语言时区 | **全池共用一把 UA**（`DEFAULT_UA`，[poolsd.py:53](poolsd.py#L53)），头序由 `_rebuild_headers` 重排成固定模板 |
| 行为像人 | 请求间隔方差、单 IP 频次 | **网关无任何节律层**；`/get` 每次随机选，同目标域会来回跳 |
| 池不被拖垮 | 坏代理占比、污染传播 | 有 EWMA + 退避，但**判死只是不选它，注入型代理永远留在池里** |

一句话：**这个池子会让 300 个不同出口在目标侧看起来像同一个人在 300 个 IP 上轮着跑。** 指纹归一化是最致命的，比 IP 质量重要一个数量级。

---

## 二、逐条发现与改造（每条挂 file:line）

### F1 全池共用一把 UA —— 最贵的缺陷

原文 [poolsd.py:53](poolsd.py#L53)：

```python
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
             "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
```

`fetch_via_proxy`（原 [poolsd.py:1012](poolsd.py#L1012)）与 `/get?format=scrapy`（`_format`）都用这一个常量。**后果**：目标侧一次聚类就把整个池归一成一个「Chrome 124 / Windows / 无 Client Hints」的客户端在 300 个 IP 上跑。TLS 层同理——全部走 `ssl.create_default_context()` 的默认密码顺序（`verified_tls_context`，[poolsd.py:169](poolsd.py#L169)）。

改造：新增 [`FingerprintBook`](poolopt.py#L562)，6 个画像桶（Chrome131-Win / Chrome124-Mac / Edge131 / Firefox128 / Firefox115-Linux / Safari17），按 `blake2b(proxy_key)` 取模固定分配——**同一出口永远同一画像**，跨进程重启不变（[poolsd.py:684](poolsd.py#L684) 的 `p.profile = self.fingerprints.assign(p.key).name`）。

每桶带三样东西：
- 头序模板（`CHROME_H2` / `FIREFOX_H2` / `SAFARI_H2`，`poolopt.py`）——真实浏览器的头序是固定的，curl 顺序是错的；
- `Accept-Language` + Client Hints（`sec-ch-ua` / `sec-ch-ua-platform`）——数据中心 IP + `zh-CN` + Windows UA 是标准错配，这里把三者绑到同一画像上；
- 密码套件串 + ALPN（`CHROME_CIPHERS` / `FIREFOX_CIPHERS` / `SAFARI_CIPHERS`），[`tls_context(profile)`](poolopt.py#L465) 应用到 CONNECT 后的二层 TLS 与 HTTPS 代理本身。

实测：400 个代理分配落在 6 桶，最大/最小 = 1.70（< 2.0 即不过度倾斜）。

### F2 头序与默认头被重排成「不像任何浏览器」的样子

原文 [`_rebuild_headers`](poolsd.py#L1492)按客户端到达顺序原样转发，只剥代理头。这在两种情况下都错：客户端是 curl（顺序天然不像浏览器），或客户端头缺项（没有 `Accept-Language`、没有 `Sec-Fetch-*`）。

改造：[`shape_request`](poolopt.py#L490)按画像模板重排 + 补默认头，规则三条：

1. `Host` 第一位，`Connection: close` 最后一位——真实客户端就是这么排的；
2. **`User-Agent` / `Accept-Language` / `Accept-Encoding` 强制覆盖成画像值**。这条反直觉但必须：curl UA 配 Chrome 密码套件，比头序稍微不自然明显得多；
3. **未知头不丢、不重排**——保留原相对顺序追加在模板之后。丢一个 `X-Requested-With` 或 Cookie 比顺序错更显眼。

实测（`hardening_test.py` [2]）：未知头 `X-Custom-Trace` 保留、`Proxy-Connection` / `Proxy-Authorization` 剥离、Cookie 原值不动、UA 替换为画像值。

### F3 网关零节律 —— 方差≈0 的机械节流

原网关（`_do_connect` / `_do_forward`）只有 `connect_timeout` / `idle_timeout`，**没有请求间隔控制**。宿主的并发数就是撞目标的频率；单出口可能被同域并发连打。

改造：[`Rhythm`](poolopt.py#L612)+ 网关接线（CONNECT [poolsd.py:1321](poolsd.py#L1321)、转发 [poolsd.py:1401](poolsd.py#L1401)）：

- **每（目标域 × 出口）独立令牌桶**（容量 5、补充 0.5/s），跨域不共享配额——一个站拖不垮全局；
- **全局令牌桶**（2/s）做总闸；
- **对数正态抖動** [`human_delay(mu=1.6, sigma=0.6)`](poolopt.py#L581)：实测 2 000 样本均值 1.882s、CV 0.667、下界 0.150s；对照组固定 `sleep(1.6)` 的 CV = 0——这就是被动检测抓的东西。

`mu=0` 或 `sigma=0` 退化为无抖动（`human_delay` 内显式判，`log(0)` 会抛 `ValueError`，这是改造中踩到的第一个坑）。

### F4 同目标域来回跳线 —— 「账号异地」的制造机

原 `pick()` 每次从 `candidates()` 里加权随机。宿主如果不传 `session`，同一站点的连续请求会落在 5 个不同出口上；登录态一跨 IP 就触发风控。

改造：[`AffinityBook`](poolopt.py#L647)+ [`pick(host=...)`](poolsd.py#L831)：

- **亲和**：同目标域在 `affinity_ttl`（默认 900s）窗口内复用同一出口；
- **冷却**：同一出口对同一目标域在 `proxy_cooldown`（默认 60s）内不再承接——防单 IP 高频。

关键取舍：**网关裸请求传 `affinity=False`，只保留冷却**。第一版把亲和默认打开，结果 A/B 双上游轮换测试直接挂了（24 发全压在 A 上）——网关是并发入口，绑亲和等于把整站压到一条线。`pick()` 因此带两个开关，`/get?host=&affinity=0` 可显式关掉。

实测（`hardening_test.py` [6b]）：同域两次同出口；异域可换；亲和过期后可换。

### F5 判活只判「能不能连」—— 注入型代理永远在池里

原 [`Checker.check_one`](poolsd.py#L1128)三道判据：状态码 2xx/3xx、200+空体判失败、`expect_contains`。**这三条都过不了下面这些**：

| 代理行为 | 原判据结果 | 目标侧后果 |
| --- | --- | --- |
| 404 改写成 200 塞广告 | 通过（200 + 有内容） | 采到假页、内容错位 |
| 不可达域名伪造 200 | 通过 | 静默丢数据 |
| 正文尾部注入 banner | 通过 | 页面被污染 |
| 泄漏 `Via` / `X-Forwarded-For` | 通过 | 一眼认出是代理 |
| 改写 UA | 通过 | 指纹错配 |
| 放行任意 CONNECT 端口 | 通过 | 滥用面 / 蜜罐特征 |

改造：[`AnonymityGate`](poolopt.py#L698)五项判据 + 加权评分（30/25/15/15/15），任一项坐实注入或篡改 → **`blacklist` 直接出池**：

| 判据 | 探针 | 判据 |
| --- | --- | --- |
| 透明性 30 | 带唯一 marker 的 UA 打目标，看回显与响应头 | 无 `Via`/`X-Forwarded-For`/`Forwarded`/`Proxy-Connection`/`X-Real-IP` 等 8 项，且 UA 未被改写 |
| 注入 25 | 必然 404 的随机路径 + 必然不可达的随机 `.invalid` 域名 | 两者都回 404/错误 = 通过；回 200/203 = 注入 |
| 篡改 15 | 同 URL 经代理取正文，与**直连基线**比 sha256 | sha 不等且长度差 > 2% = 篡改；< 2% 记为「动态内容」不判负 |
| 一致性 15 | 两次 cache-buster 取长度变异系数 | CV < 0.02 = 稳定 |
| 端口面 15 | CONNECT 到 22 / 25 / 6379 | 全拒 = 只放行 HTTP |

**基线纪律（改造踩到的第二个坑）**：比对类探针必须两侧发**同一组头**。第一版直连基线不带 UA、代理探针带画像 UA，目标回显 `received:{...ua}` 让正文长度差 76%，干净代理被判成篡改。现在 [`probe_headers()`](poolopt.py#L48) 固定一组，直连与代理两侧共用。

第三个坑：`content_check` 默认必须 **False**。L2 内容一致性对「回显请求头」的目标（`httpbin/ip`、`gcecho`、任何 echo 型靶场）天然不成立，默认开会把健康代理全判死——`smoke.py` 第一版就这么挂了（`体检通过 2 条 → ok:0`）。要开就配静态目标（`generate_204` 这类空体、或固定内容的静态文件）。

评分写回：[`ProxyPool.apply_audit`](poolsd.py#L755) 把 `grade` 落到代理对象与 SQLite，[`_score()`](poolsd.py#L705) 里 `degraded×0.7 / unusable×0.1 / blacklist=0`，[`candidates()`](poolsd.py#L793) 双保险再过滤一次 `blacklist` 集合。

实测（`hardening_test.py` [5]）：干净代理 `usable 100.0`；注入代理 `blacklist`（`fake_404=True`、`leaked_headers=['via','x-forwarded-for']`）；注入代理 L2 判不一致。

### F6 公共源 = 别人的蜜罐 + 信誉污染

`pool.json` 默认启用 monosans 两个列表（`public_sources`，各上限 80）。`public_sources.py` 的边界做得不错（只允许 `raw.githubusercontent.com` 的 HTTPS `.txt`、1 MiB、只收全球可路由 IPv4、拒绝带凭据、先验后用），但**它挡不住的是源本身**：

- monosans 列表里相当一部分是 honeypot / 已滥用段，入口 IP 直接进各类 reputation 库；
- 这些代理的 TLS 指纹、转发头、注入行为**完全不可控**，你只能事后把它判死；
- 抓源时拉的 `raw.githubusercontent.com` 与使用时代理出口无关联，但**源站能看到谁在拉**（User-Agent 是固定的 `ProxyPool-public-sources/1.0`）。

改造建议（已落进代码路径，默认未改行为）：
- 保持 `enabled: true` 只在低价值采集时用；登录态/支付/后台一律只走私有清单；
- 新导入的公开代理默认 `enabled=False`，必须过 `AnonymityGate` 五判据才启用（这条仓库原本就有了，改造把它接到了 `deepseek`/`/audit` 上）；
- `public_sources` 的 `max_entries` 建议压到 30 以下——80 条里能过五判据的通常不到 10 条，多拉只是多污染池子。

### F7 判死只判「不用」，不判「永不用」

原状态机 `dead → 退避 60s×2^n → 复活`。对「时好时坏」的代理这是对的，**对「注入型」代理是错的**——注入行为是代理运营方的固定策略，退避到期后它会继续注入，而它每次复活都污染一批请求。

改造：`blacklist` 是**与 dead 正交**的第三态（[poolsd.py:772](poolsd.py#L772) 的 `clear_blacklist` 需人工放行）。`apply_audit` 坐实注入/篡改 → 入集合 + `enabled=False` + `dead_until=now+86400`；`pick()` 永不给。实测：200 次选路 0 命中。

### F8 SOCKS5 域名远端解析

原 `_socks5_handshake`（[poolsd.py:948](poolsd.py#L948) 附近）已经是 `0x03` ATYP 传域名——**这条本来就是对的**。改造里 `_socks5_connect`（`poolopt.py`）保留同样逻辑，并在 `proxy_fetch` 里统一走 `socks5h` 语义（域名交给代理解析，不在本地 DNS 泄漏）。

需要注意：`open_tunnel` 里 `socks4` 走的是 SOCKS5 握手（README 已自述未实测），别用。

### F9 网关不传 `host` 给选路 → F4 失效

第一版改完 `pick()` 支持 `host` 但网关没传（`_do_connect` / `_do_forward` 仍 `pool.pick()`），冷却与亲和完全不生效。已修（[poolsd.py:1321](poolsd.py#L1321)、[poolsd.py:1401](poolsd.py#L1401)）。这类「改了组件没接线」是改造里最常见的漏，`hardening_test.py` [7] 用真实进程 + 真实 socket 端到端断言才抓得住。

### F10 `/stats` 不暴露隐蔽性状态

加：`blacklist`、`by_grade`（`usable/degraded/unusable/unchecked`）、`fingerprints`（桶分布）、`affinity`（{affinity, recent_pairs, hosts}）。Prometheus `/metrics` 加 `proxy_pool_blacklist`、`proxy_pool_grade{grade=}`、`proxy_pool_fingerprint_bucket{profile=}`、`proxy_pool_affinity_pairs`。

新端点：

| 端点 | 作用 |
| --- | --- |
| `POST /audit` `{ids?}` | 五判据全量体检，返回 `{checked, usable, degraded, blacklist, unusable, error}` |
| `GET /audit/detail?id=` | 单代理五判据明细 |
| `GET /blacklist` / `DELETE /blacklist` `{keys?}` | 查/人工放行 |
| `GET /hardening` | 当前节律、亲和、桶分布、网关开关 |
| `POST /rhythm` `{mu,sigma,per_key_qps,global_qps,affinity_ttl,proxy_cooldown}` | 运行时调参，不重启 |
| `GET /get?host=&affinity=0` | 带冷却、不绑亲和（并发抓取用） |

`poolclient` 同步：`audit()`、`audit_detail()`、`blacklist()`、`clear_blacklist()`、`hardening()`、`set_rhythm()`、`get(headers=...)` / `get_headers()`（拿出口画像的头，避免宿主自己发 curl UA 把画像白做）。

---

## 三、违规路径：机制、能不能骗过检测、怎么被抓住

题目要求包含违规。这里做工程评估，不写使用建议——判断标准只有一条：**目标能不能把你聚类**。

### V1 「借用」他人开放代理（扫 1080/3128/8080 拿来用）

- **机制**：无认证 open proxy 直接当出口。
- **为什么能骗过一部分检测**：它确实是真代理，HTTP 层完全正常。
- **代价**：你把自己的 Cookie / token / 请求体完整交给了一个陌生人——这是**攻击面反转**，不是隐蔽性提升。运营方可记录、可篡改、可回放你的认证态。
- **怎么被抓住**：出口 ASN/rDNS + abuse 库；受害机主看到异常出站；你无法知道中间人做了什么。
- **对本仓库**：`proxies.local.txt` 里放这类地址等于把整个采集链的凭据托管出去。

### V2 SDK 静默转发（把第三方设备变出口）

- **机制**：App/SDK 内置转发模块，借终端网络转发他人请求。
- **为什么有效**：住宅 ASN 天然高信誉，设备指纹自然（真机真浏览器）。
- **怎么被抓住**：后台常驻连接 + 电量/流量异常；证书校验失败；商店政策扫描；一旦逆向，转发域名与协议 10 分钟内暴露，且构成可举证的证据链。
- **对本仓库**：与代码无关，但与「私有清单该放什么」直接相关——这类来源的合规状态绑定在别人身上，段级封禁随时整段失效。

### V3 僵尸网络节点

- 出口分散、真实家宽，骗得过 IP 信誉。
- 被 EDR 出站异常、C2 心跳节律、DNS 隧道特征抓住；出口进 DDoS/abuse 黑名单后整段被墙。
- 属刑事案件范畴；节点在 EDR 普及后存活率极低。

### V4 住宅代理供应商的「来源合规」缺口

- 供应商声称 P2P 众包，实际混入未充分告知的设备。
- 你看 IP 质量看不出，供应商侧审计/投诉/段级封禁才知道。
- **工程结论**：可用性绑定在别人的合规状态上，是供应链风险而非技术风险。

### V5 Tor 出口

- 骗得过简单地域限制。
- 公开 Tor 出口列表几百个 IP 全量比对，命中率接近 100%；入口守卫节律 + TLS 指纹。
- 只适合低价值低频非登录态；登录态一用即毁号。

### V6 MITM 证书替换

- 只对无 pinning 的站点有效。
- 证书链签发者变化、CT 日志无记录、pinning 直接失败。
- 对现代 App 与主流站点直接失效，暴露成本极高。

### V7 IP 洗白（伪造 WHOIS/rDNS 成家宽）

- 只骗得过单一数据源。
- 多源交叉（IPinfo + MaxMind + rDNS + whois 时间线）不一致即标记；新注册段 + 高流量是强特征。
- 成本收益最差的一条。

### V8 本仓库自带的 `direct_nodes`（CDN 直连节点）——需要单独说

`direct_nodes.py` + `pool.json` 的 `allowed_hosts: ["kyfw.12306.cn"]` + README 第十九节：这是**目标站 CDN 边缘 IP 目录**，按 SNI 直连 TLS 端点绕过前置调度。

- **机制**：拿到边缘节点 IP + 正确 SNI，直连 443，跳过 DNS/负载均衡层。
- **它明确不是代理**：不进程 `/get`、不进健康检查、`is_proxy: False`，代码层面隔离做得干净。
- **违规性质**：12306 的用户协议明确禁止自动化刷票与绕过排队；这类直连节点目录的用途基本只有一个。README 自己也写了「不包含自动注册、批量创建账号或绕过目标平台限制的流程」，但节点目录本身的服务对象就是那个流程。
- **怎么被抓住**：SNI 一致但 TLS 指纹不是浏览器、请求节律机械、同 IP 高频、购票行为与账号画像不符——风控侧看到的是「一个浏览器指纹在 171 个边缘 IP 上跳」。
- **工程结论**：这是整个仓库里违规风险最高的一块，且与「代理池隐蔽性」是两件事。要保留就把 `allowed_hosts` 收紧到自有域名；要合规就删掉这一段（代码可留，配置清空）。

### 违规路径的统一判据

不看「能不能连上」，看**三个稳定特征是否被聚类**：TLS 指纹 + 行为节律 + 出口一致性。这三条与 IP 是否住宅无关——这就是为什么第二、三节的改造比换更贵的住宅 IP 有效一个数量级。

---

## 四、验收记录（真实执行）

| 套件 | 命令 | 结果 |
| --- | --- | --- |
| 隐蔽性工程层 | `python hardening_test.py` | **全部通过**（8 组、40 项断言） |
| 内置自测 | `python poolsd.py --selftest` | 全部通过（原 18 项 + 改造后仍绿） |
| 端到端冒烟 | `python smoke.py` | **全部通过**（含 A/B 双上游轮换、CONNECT 字节回读、死代理换线、SOCKS5 隧道） |
| 报文边界 | `python framing_test.py` | Ran 7 tests / OK |
| 响应完整性 | `python response_test.py` | Ran 14 tests / OK |
| 调度会话 | `python rotation_test.py` | OK |
| 公开来源 | `python public_sources_test.py` | OK |
| 认证面 | `python auth_test.py` | 全部通过 |
| 安全回归 | `python security_test.py` | Ran 6 tests / OK（见下方注） |
| 直连节点 | `python direct_nodes_test.py` | Ran 4 tests / OK（见下方注） |

**注（环境限制，不是代码缺陷）**：`security_test.py` 与 `direct_nodes_test.py` 用 `tempfile.TemporaryDirectory()`。本机 DSH 沙箱为 `workspace-write`，**禁止在运行时新建的临时子目录里写文件**（`mkdtemp` 成功、`open(...,'w')` 报 `PermissionError`）。直接 `python verify.py --fast` 因此显示这两项 FAIL。用预建目录替身跑同一批测试用例：

```
Ran 31 tests in 25.025s
OK
RESULT ok=True
```

31 项 = framing 7 + response 14 + security 6 + direct_nodes 4，全绿。这是沙箱写权限问题，与改造无关；在有完整写权限的环境直接 `python verify.py` 即可。

### 改造中真实踩到的五个坑（都已在代码里修掉）

1. `human_delay(mu=0)` → `math.log(0)` 抛 `ValueError`。修：显式退化。
2. 比对探针两侧头不一致 → 回显型目标把干净代理判成篡改（差 76%）。修：`probe_headers()` 两侧共用。
3. `content_check` 默认开 → echo 型体检目标把健康代理全判死。修：默认 `False`。
4. 网关绑亲和 → A/B 双上游轮换失效（24 发全在 A）。修：网关传 `affinity=False`。
5. 改了 `pick()` 没接线网关 → 亲和/冷却完全不生效。修：`_do_connect` / `_do_forward` 传 `host`。

---

## 五、落地顺序（按投入产出）

1. **先跑 `POST /audit` 把现有池洗一遍**。`blacklist` 直接出池，通常能砍掉 30–50%，异常率立刻下降。
2. **开画像分桶**（已默认开）。这一步不需要任何外部依赖，是纯代码收益。
3. **确认网关 `rhythm_enabled: true`**，把 `rhythm_mu` 按目标站点容忍度调（列表页 1.5–3s，详情页 3–8s）。
4. **宿主改用 `poolclient.get_headers()`** 拿出口画像的头——否则出口是 Chrome、宿主发 curl UA，画像白做。
5. **登录态/支付/后台一律 `/get/{session}` + `host=`**，不要裸 `/get`。
6. **最后才考虑换出口类型**（住宅/移动）。前面五步没做，换再贵的 IP 也会被同一个指纹聚成一堆。

---

## 六、文件清单

| 文件 | 变化 | 说明 |
| --- | --- | --- |
| [`poolopt.py`](poolopt.py) | **新增** 37 672 B | 传输层 / 指纹桶 / 节律 / 亲和 / 五判据体检，不 import `poolsd`，可独立测试 |
| [`poolsd.py`](poolsd.py) | 90 363 → 104 241 B | 接线、`apply_audit`、`blacklist`、`pick(host, affinity)`、`_rebuild_headers(profile)`、5 个新端点、`/metrics` 4 个新指标 |
| [`poolclient.py`](poolclient.py) | 11 826 → 14 249 B | `audit/blacklist/hardening/set_rhythm`、`get(host, affinity)`、`get_headers()` |
| [`pool.json`](pool.json) | 1 615 → 2 074 B | 加 `hardening` 段、`gateway.rhythm_enabled/shape_headers`、`checker.content_check: false` |
| [`hardening_test.py`](hardening_test.py) | **新增** 28 181 B | 8 组 40 项断言，含真实进程端到端 |
| [`rotation_test.py`](rotation_test.py) | 改 1 处 | `FakeClient.get()` 接受 `host` / `affinity` |
| [`security_test.py`](security_test.py) | 改 1 处 | 同上 |
| `_upstream/poolsd.py` | **新增** | 上游原样副本，用于对拍 |