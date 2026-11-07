# 验证记录

## 验证范围

正式 module 路径为 `github.com/emhha/netloom`，根包仍为 `netloom`。本记录仅描述独立 SDK 的验证结果；发布与远程服务不属于本地测试的证明范围。

工具链：Go 1.26.3 linux/amd64、Python 3.14.8。

完整命令：

```sh
GOCACHE=/tmp/netloom-go-cache make check race integration-compile integration-local
git diff --check
```

## 本轮结果

上述完整命令退出码为 0。

| 检查 | 结果 |
| --- | --- |
| `make check` | 通过：格式、维护中文档链接和隐私约束、module/包边界、17 个 Python 离线测试、50 个固定字典文件校验、全包单元测试、vet、构建 |
| `make race` | 全包通过，无已报告数据竞争 |
| `make integration-compile` | 所有 integration 用例编译通过，不能据此声称执行过外部服务 |
| `make integration-local` | 通过；明确排除外部 Python Cookie 服务用例 |
| `go mod tidy -diff`（离线） | 通过，无依赖文件差异 |
| 独立调用方导入 | 使用本地源码离线导入根包、`httpdata` 和 `httpdata/netloomdata`，创建/关闭 Engine，测试通过；不证明远程可获取性 |
| `git diff --check` | 通过 |

构建期间出现模块统计缓存只读的非致命警告，相关命令仍退出 0；未为消除警告而修改全局 Go 配置。固定资源的原始字节、校验值及许可证保持不变。

## 覆盖边界

- 集成编译不等于执行；`integration-local` 显式排除需要外部 Python Cookie 服务与固定 DNS 的用例。
- 不调用真实付费 API，不使用实际服务凭据；mapping 包尚无包内协议测试，不能把编译成功当作服务验收。
- 不捆绑或下载第三方 MMDB；真实数据内容、城市/ASN/Country 查询仍需使用具备许可的数据另行验证。
- 规则与字典固定快照可离线校验；本地测试不证明远端版本可达、最新或具备再分发授权。

## HTTP 可靠性第一阶段补充验证

工具链仍为 Go 1.26.3 linux/amd64、Python 3.14.8。实施范围见 [能力计划](HTTP-CAPABILITIES-PLAN.md)，公开行为见 [API](API.md) 和 [升级说明](UPGRADING.md)。

最终实现执行以下完整命令，退出码 0：

```sh
make check && make race && make integration-compile && make integration-local && git diff --check
```

| 检查 | 结果 |
| --- | --- |
| `make check` | 通过：格式、仓库/文档检查、17 个 Python 离线测试、50 个字典文件校验、全包测试、vet、build |
| `make race` | 全包通过，无已报告数据竞争 |
| `make integration-compile` | 所有集成测试编译通过 |
| `make integration-local` | 本地集成通过，包括自定义信任/mTLS、代理、流式生命周期；明确排除外部 Python Cookie 服务 |
| `git diff --check` | 通过 |

附加定向验证：

```sh
go test . -run '^Test(Reliability|PartialResponse)' -count=1
go test -race -tags=integration . -run '^Test(Reliability(BodyTimeout|ProxyBodyTimeout|SubMillisecondStreamTimeout|EngineCloseInterruptsBlockedRead)|ProxyIsUsedBySendAndStream)' -count=10
```

定向测试通过；最终直连/代理超时与关闭竞争用例在 race 下连续执行 10 次通过。fake transport 覆盖最近非 nil 响应、后续无 headers 失败、取消/地址阻止、重试成功、Run 证据及有效超时副本。本地服务覆盖配置/请求/context 期限、正文阻塞、亚毫秒期限、H1/H2 实际协议与单连接证书 SHA256、部分正文和流式完成状态；不访问外网。

中间验证曾暴露两个问题，均修复后重跑，而非跳过失败用例：客户端计时器与 context 同时到期导致读取错误原因不稳定；禁用客户端计时器时，依赖库 CONNECT 拨号器将零超时视作立即到期。最终由 context 管理精确期限，直连禁用独立客户端计时器，代理保留正值毫秒向上取整的兼容期限；读取失败按有效 context 期限归因。相关场景已加入回归。

早期检查曾因构建缓存只读被沙箱阻止，不能算通过；最终在允许写入缓存的执行环境完成以上命令。未修改全局 Go 配置，未运行外部 Cookie 服务、真实付费 API 或远程目标测试。

本阶段不证明连接池复用/隔离、显式 H2 策略、HTTP/3 或高级 DNS/路由能力已经实现。Raw 尚未提供普通路径的完整 Timings；缓冲 QueueMS 暂不测量。

## 2026-11-07：阶段 2A 连接池与 HTTP/2

工具链：Go 1.26.3 linux/amd64、Python 3.14.8。完整执行并退出码 0：

```sh
make check && make race && make integration-compile && make integration-local && git diff --check
```

- `make check`：格式、文档/仓库检查、17 个 Python 离线测试、50 个固定字典文件校验、全包测试、vet、build 通过。
- `make race`：全包通过，无已报告数据竞争。
- `make integration-compile`：所有集成测试编译通过。
- `make integration-local`：本地 TLS/mTLS、代理、流式生命周期集成通过；仍明确排除外部 Python Cookie 服务。
- `git diff --check`：通过。

定向重复验证（均退出码 0）：

```sh
go test -race . ./nethttp -run 'Test(ConnectionPool|ClientDialScope|HTTP|BuildRequest)' -count=5
go test -race . -run '^Test(ClientDialScope|ConnectionPoolStaleHTTP2)' -count=10 -timeout=45s
```

覆盖 H1/H2 缓冲与流式顺序复用、默认不复用、FreshConnection、容量等待/取消、空闲 LRU/TTL、origin/代理/验证配置隔离、自定义 TLS/Profile 一次性租约、Cookie 会话与客户端驱逐独立、EOF/提前关闭/读取失败释放，以及实际连接 IP/TLS/timings。适配层验证显式 H2 值、FreshConnection 和隐式默认 Profile。严格 H2 使用同一次 TLS 握手的真实 ALPN：H1/no-ALPN/明文目标收到零次 HTTP 请求；本地 H2、自定义信任/mTLS、Cookie/URL BasicAuth、HTTP CONNECT 认证与取消通过。

中间失败/审查问题均修复后重跑：HTTP 代理接线曾同时设置两个不兼容的第三方选项，配置校验失败；CONNECT 取消有时被暴露为 socket 错误而非 context 因果链；底层 H2 过期连接重拨使用 background context，可能在 TLS 初始化时无限等待。最终 HTTP CONNECT 采用自有 context-aware 交换，拨号/握手错误按有效 context 归因，原始连接按当前独占租约绑定取消，并在成功归还前等待旧取消回调结束。重连回归先完成真实 H2 请求、关闭旧连接，再让新连接停在 TLS 握手，缓冲/流式的请求期限、取消与 Engine.Close 均在 race 下连续 10 次通过，且观察到 stalled socket 关闭；不是只验证外层调用提早返回。

范围限制：默认不启用池；MaxClients 约束客户端条目/租约而不是所有 TCP socket 的精确总数。首版不提供同客户端 H2 并发 multiplexing，不缓存显式 Profile、TLSOptions、严格 H2 或非 HTTP 代理 scheme，Cookie 会话内存未设独立上限。严格 H2 仅直连及 HTTP CONNECT；非严格模式保留其他代理 scheme，但其第三方拨号器仍有实时取消限制。未验证外部网络、外部 Cookie 服务、HTTP/3、阶段超时/结构化阶段错误或性能收益；阶段 2B 及后续能力仍是计划。

## 2026-11-07：阶段 2B 阶段超时与错误归因

工具链：Go 1.26.3 linux/amd64、Python 3.14.8。最终代码执行以下完整命令，均退出码 0：

```sh
go test -race . ./nethttp -run 'Test(Phase|BuildRequestPhase|ConnectionPoolStaleHTTP2|HTTPProxyCONNECT)' -count=5 -timeout=90s
make check && make race && make integration-compile && make integration-local && git diff --check
```

- 定向 race 回归连续 5 次通过（根包 25.934s，nethttp 1.019s）。
- `make check`：格式、维护文档/仓库边界、17 个 Python 离线测试、50 个固定字典文件校验、全包测试、vet、build 通过。
- `make race`：全包通过，无已报告数据竞争。
- `make integration-compile`：所有集成测试编译通过，不能据此声称执行了外部服务。
- `make integration-local`：本地集成通过；明确排除外部 Python Cookie 服务。
- `git diff --check`：通过。

H1/H2/严格 H2 覆盖实际 POST 写完后无响应、103 和不完整最终响应头、TLS stall 与真实过期 H2 后台重握手、HTTP CONNECT stall，以及正文部分字节之后阻塞。观察到 stalled socket 被关闭、容量可回收；复用连接不会错误启动新的 TLS timer。BodyIdle 逐次阻塞读取计时，持续小块进展可跨越单次 idle 时长，流式调用方暂停消费不误超时。池满等待受单次 Timeout/Total 控制，不提前启动 Connect/TLS/header timer，取消等待不窃取原租约。测试同时覆盖配置继承/请求整组零覆盖、负值/毫秒溢出、更早的 caller deadline、取消 cause 保留、stream Status 与 Engine.Close、Raw 部分响应/100/103 最终头，以及跨重试/Do 多跳/跳转校验的 Total。

中间验证发现问题后修复重跑：POST stall 测试服务必须先读完请求体，才能可靠通过服务端 context 观察断连，避免测试 cleanup 停滞；socket deadline 可能先于 context timer 发布 cause，此时记录有效 Total deadline 归属并停止继续重试，避免总预算被误归为 connect/body。该 Total 回归另以 `go test -race . -run '^TestPhase(RawTotal|TimeoutTotal)' -count=15 -timeout=45s` 连续 15 次通过。独立复核还发现 Do 归一化丢失 Canceled 身份、流式旧归一化剥掉阶段包装；最终用例分别验证 errors.Is(Canceled/Deadline/自定义 cause)、errors.As(PhaseError)、部分 Response.Error 和 StreamStatus.Error。

范围限制：本阶段不证明精确纯 TLS 握手测量、HTTP/3、外部网络/代理兼容性、上传 replay、按方法安全重试或性能收益。TLSHandshake 实际覆盖 TLS 至 HTTP-ready/H2 初始化；非零策略只支持直连和 HTTP 代理。Send/Run/Stream 的 Total 不包含初始准入排队；Do 外层预算包含其内部 Send 排队。未运行外部 Cookie 服务、真实付费 API 或远端目标。前面的阶段记录保留历史边界，当前已实现能力以本节及 [API](API.md) 为准。

## 2026-11-07：阶段 3A 直连映射与地址族

工具链：Go 1.26.3 linux/amd64、Python 3.14.8。最终实现执行以下命令，退出码均为 0：

```sh
go test -race . ./nethttp -run 'Test(Network|BuildRequestNetwork|ConnectionPoolStaleHTTP2)' -count=5 -timeout=90s
make check && make race && make integration-compile && make integration-local && git diff --check
```

- 定向 race 连续 5 次通过：根包 5.257s、nethttp 1.046s。独立测试实现还执行映射协议用例 `go test -race . -run '^TestNetworkTransport' -count=5 -timeout=60s`，通过（1.861s）。
- `make check`：仓库/文档/格式边界、17 个 Python 离线测试、50 个固定字典文件、全包测试、vet、build 通过；根包测试 10.964s。
- `make race`：全包通过，无已报告数据竞争；根包 12.785s。
- `make integration-compile`：全部集成用例编译通过；`make integration-local` 本地集成通过（根包 11.008s），明确排除外部 Python Cookie 服务。
- `git diff --check`：通过。验证记录追加后重新执行文档/格式检查。

真实本地 TLS 服务覆盖 H1/H2/严格 H2、缓冲/流式/Raw 的原始 URL、Host/SNI、验证证书名、实际 IP 与 TLS 证据；错误逻辑证书名在发 HTTP 前失败。无 DNS resolver 夹具检查显式映射无逻辑/替换主机解析及 CNAME 补查；池用两端点验证规范等价策略复用、不同目标/地址族隔离。重定向逐跳重算规则，保留逻辑 URL 校验与跨 origin 授权/Cookie 清理。真实过期 H2 重连另增加映射主机夹具，验证当前租约策略与 TLS 阶段取消。

生产地址保护开启的 planner 测试使用受控本机 UDP DNS 与模拟最终 literal 拨号，检验 family 过滤、IPv4-mapped 规范化、受阻实际 IP、允许 RFC1918、候选顺序/预算/无隐式 DNS 回退。受阻逻辑 IP 在池获取前检查；末尾点等规范等价拼写不绕过保护。独立审查发现末尾点 IP 检查不一致及混合候选错误禁用重试，修复后新增规范逻辑 IP 拦截和两种候选顺序下允许地址临时失败后重试成功回归，再通过上述完整检查。适配输入覆盖 JSON、规则上限/重复/无效字段与深拷贝。

范围限制：仅直连映射，不支持代理端解析/出口 family、自定义 DNS server 配置、Happy Eyeballs 或新 TLS 参数；任何非零策略与代理均明确拒绝。默认 nil/空/auto 保持旧行为。真实证书/协议测试仅测试内部禁用地址类别保护以访问本机，不能据此声称允许生产访问 loopback；保护开启的 DNS/family 验证不向文档地址实际发包。未执行外部 Cookie 服务、远端代理/目标或性能验收。TLS min/max、显式 ServerName 与 pinning 仍属后续阶段 3B。
