# 验证记录

## 2026-11-19：序列化插件目录迁移

Go 1.26.3 linux/amd64。`make check race integration-compile` 通过，集成目标仅编译。原有规则等价、扫描预算和结果测试在新包路径执行；旧类型别名和新构造函数由兼容性测试覆盖。仓库路径检查的 21 个 Python 离线测试通过。

## 2026-11-19：将信息提取收为独立注册的被动插件

Go 1.26.3 linux/amd64。`make check race integration-compile` 通过，集成目标仅编译。离线用例覆盖插件规则扩展、AC 与正则匹配、并发规则更新和正文及响应头去重。主动流量与 HTTPS MITM 的本地回归均通过新路径注册插件。仓库检查新增旧目录和旧导入拒绝用例，20 个 Python 离线测试通过。来源记录保留原上游路径与哈希。

## 2026-11-19：按响应元数据跳过重复信息提取

Go 1.26.3 linux/amd64。`make check race integration-compile` 通过，集成目标仅编译。离线测试覆盖等长更新按默认配置跳过且不重发旧发现、长度变化后重新分析、响应头独立检查、截断长度缺失、规则更新清除完成标记，以及启用正文哈希后能够区分等长内容。Registry 测试同时保留普通缓存的旧结果复用语义，并验证只去重模式不持有发现。用本地 TLS 源站和 CONNECT 代理验证了跨主动入口与 MITM 的去重。此次未测量吞吐或 CPU 使用率。

## 2026-11-19：HTTP 流量分析入口与缓存复用

工具链 Go 1.26.3 linux/amd64。执行并通过 `make check race integration-compile` 与 `git diff --check`。本机 TCP 监听在沙盒内被拒绝，完整检查在允许本机临时端口的环境执行。`integration-compile` 只编译带 tag 的测试。

- 本地 TLS 源站与两个 CONNECT 转发服务覆盖 `Send`、`SendStream`、`PrepareTask` 和 HTTPS MITM。用例检查共享代理和单请求覆盖、gzip bytes 原样转发，比较接入分析前后主动请求的 TLS 版本、密码套件和 ALPN，比较时排除预期随机变化的 GREASE 值。
- 同一合成 JS 经过主动和代理入口时命中同一正文缓存，变化的响应头独立分析。同一 URL 的正文变化会得到新结果。四次交换各交付一次报告，内容缓存测试插件只执行两次。队列回归覆盖流式采集上限、提前关闭、报告丢弃计数和回调阻塞时继续转发。
- 以上检查验证调用次数、缓存命中和传输行为。没有测量吞吐、延迟或峰值内存，也没有访问外网代理或真实站点。

## 2026-11-11：调度并发、主机回收、代理与 API 查询安全

工具链 Go 1.26.3 linux/amd64、Python 3.14.8。执行并通过：

```sh
go test . ./httpclient ./nethttp ./internal/proxyconfig
go test -race . ./httpclient ./nethttp ./internal/proxyconfig -run 'Proxy|CurlUnsupported|TestParse$' -count=1
go test -race . -run '^Test(EngineLifecycleRegression|HostSemaphore|EngineSendReleasesDistinctHostState|SchedulerHostErrorHistoryIsRunScoped)' -count=10 -timeout=180s
go test -race ./mapping ./enterprise -count=5 -timeout=90s
go test -race ./httpclient -run 'Test(RetryMethods|PostRetriesRequireExplicitMethod|RetryCountsAndDisablePrecedence|DoRetryBodyReplayGate|DoGetBodyFailureStopsBeforeSend|DoEmptyBodiesAndExactMethods|ExplicitPostRetryCanceledAfterResponse)' -count=20
make check && make race && make integration-compile && make integration-local
git diff --check
```

- `make check` 的格式、文档/仓库边界检查、19 个 Python 离线测试、50 个固定字典文件校验、全包默认测试、vet 和构建通过。全包 race 通过，无已报告数据竞争；根包为 23.651s，部分已验证包使用 Go 缓存。
- scheduler 回归用 channel 屏障和注入 transport 检查初始化完成后发布、Run/Submit/Close 启动竞争、single-flight/复用、多个 Close 等待在途工作和结果通道关闭。主机测试检查等待者与持有者共享同一配额、取消后安全回收、不同主机 Send 无空闲槽残留、成功重置计数、跳过在 Run 内 sticky、Run 结束释放错误历史 map。最终这组 race 重复 10 轮通过（1.892s）。重复竞争不是全部线程交错的证明，单个长期 Run 的不同失败主机历史仍可能增长。
- 代理测试覆盖共同解析和各包支持集合、入口和 transport/retry 后备校验、Mutators 修复/制造无效配置、限流/准入/GetBody/发送前拒绝、错误及日志不回显代理凭据，以及配置错误不计目标失败。本地 HTTP 转发/认证和 CONNECT 取消有实际网络回归；HTTPS/SOCKS 的语法与构造验证不代表这些外部代理端到端验收。
- 凭据 fake reader/client 检查存储失败/取消/deadline 的错误链、同时返回字节和错误时禁止发送、缺失/空白与读取故障分离、FOFA 的分页快照和后续轮换、三个测绘引擎 trim/轮换及窄客户端接口、爱企查五个 API 与既有字段校验顺序。mapping/enterprise 最终 race 重复 5 轮通过（1.084s/10.028s），没有真实数据源请求。
- 会话重试测试检查 GET/HEAD/OPTIONS 默认列表、POST 显式允许、nil/空/非法列表与配置复制、空方法及大小写精确匹配、正文双重门禁、次数开关优先级、GetBody 失败、响应体排空/关闭和最终所有权、网络耗尽与取消错误链。专项 race 重复 20 轮通过（1.437s）。这只验证 SDK 循环，不承诺业务幂等、账单去重或 exactly-once；底层 Transport 仍可能透明重发。
- 集成编译仅证明带 tag 的代码可编译；另执行 `make integration-local`，根包为 17.600s，真实运行受控本地 TLS/mTLS、代理及流关闭等回归。该目标明确排除根包/probe 的 `TestPythonCookieServerE2E` 外部 Cookie 服务用例，不将其排除或其他环境分支的跳过计作验收通过。未修改 DNS/hosts 或关闭生产拨号保护，未访问真实付费 API 或外网目标，也未执行吞吐/峰值内存验收。
- 初次仓库检查将共享私有解析包误判为扩展依赖；仅为 `internal/proxyconfig` 增加精确允许项，同时反向检查其不得依赖运行时/扩展，并补充离线允许/拒绝用例，未放开其他内部包或 httpdata 的边界。早期 curl 负例误用了已支持的短选项前缀，重试测试误比较被 http.Client 超时包装的正文指针；分别修正夹具和行为断言后重跑通过，没有通过放宽生产约束或跳过断言规避失败。

## 2026-11-11：目录扫描有界并发与聚合

工具链 Go 1.26.3 linux/amd64、Python 3.14.8。执行并通过：

```sh
go test ./dirscan
go test -race ./dirscan -run '^TestScanConcurrency' -count=30 -timeout=90s
make check && make race && make integration-compile
git diff --check
```

- `make check` 的格式、文档/仓库检查、17 个 Python 离线测试、50 个固定字典文件校验、全包默认测试、vet 和构建通过。全包 race 通过，dirscan 为 3.286s；未受影响的部分包使用 Go 缓存。集成测试仅编译，不视为集成服务执行证据。
- 新增回归通过 fake engine 和 channel 屏障验证 Threads 1/3/7 的真实重叠与峰值上限、默认窗口 30、慢队首时已完成的乱序响应继续占用窗口，以及派发序的结果、去重与 wildcard 分类。
- 验证取消/手动触发的 deadline 错误传播、成功乱序响应保留、返回前全部 worker 退出；原生命周期测试仍覆盖真实 context deadline、公开入口预取消和准备前 MaxTime 到期。未声称真实网络扫描中途 MaxTime 的端到端覆盖。
- 验证 Send error、nil 响应和 Response.Error 连续失败计数、成功重置、阈值后成功尾部响应不会恢复派发；验证串行 Crawl 优先、并发 Crawl 的固定根/深度与目录串行，以及四种正文词数/行数过滤。
- 最终专项 race 重复 30 轮通过（3.320s），未报告数据竞争。早期测试失败来自默认扩展补齐、自链接正文和屏障观察计数的夹具问题；修正后重跑通过，没有用放宽生产保护或跳过断言代替修复。
- 窗口只限制请求与未聚合响应，不限制整个字典、发现队列和结果总量。fake engine 验证 worker/协调器契约，不证明真实网络同主机吞吐或性能收益；未访问外网、真实付费 API 或外部集成服务。

## 2026-11-10：请求变换、扫描生命周期与规则缓存

工具链 Go 1.26.3 linux/amd64、Python 3.14.8。执行并通过：

```sh
go test . ./probe ./dirscan ./infoextract ./passive/plugins
make check && make race && make integration-compile
git diff --check
```

- `make check` 的格式、文档/仓库检查、17 个 Python 离线测试、50 个固定字典文件校验、全包默认测试、vet 和构建通过；部分未受影响测试使用 Go 缓存。
- 全包 race 通过，无已报告数据竞争；集成测试仅编译，不将其视为集成服务执行证据。
- Task Mutators 回归验证顺序、线上实际方法/URL/请求头/正文、原请求隔离、重试不重复变换、变换错误阻止发送与分析，以及响应上下文中旧适配器的明确错误；probe 回归验证请求构造时设置选项、自定义 User-Agent 优先及响应提取不运行 mutator。
- dirscan 使用 fake engine 验证实际递归/Crawl 队列的固定根深度、非根 BaseURL 的相对/绝对链接及根外拒绝、取消/deadline 的空或部分结果和错误传播。公开入口覆盖预取消和准备前 MaxTime 到期；未声称真实网络扫描中途 MaxTime 的端到端覆盖，未改变同步扫描模型。
- infoextract 与 Information 验证新增/替换/失败规则更新、跨实例身份、旧在途 Registry 完成不污染新代，以及并发 AddRule 时正文/响应头的同代次一致性。
- 初次验证被默认 Go 缓存写权限阻止；缓存允许写入后以正常 Go 配置重跑。中间出现的测试编译错误已修复，没有跳过测试或变更全局 Go 配置。本次未执行外部服务、真实付费 API、外网目标或性能验收。

## 2026-11-10：Cloudflare 共享 AC 接入

工具链 Go 1.26.3 linux/amd64、Python 3.14.8。共享 `ac` 薄适配固定版本 `github.com/cloudflare/ahocorasick v0.0.0-20240916140611-054963ec9396`；本条是接入后验证，区别于下方仅评选库的历史记录。执行并通过：

```sh
go mod tidy
make check
make race
make integration-compile
go test ./passive/plugins -run '^$' -fuzz '^FuzzSerializationACEquivalence$' -fuzztime=5s -parallel=2
git diff --check
```

- `make check` 的格式/文档/仓库检查、17 个 Python 离线测试、50 个字典文件校验、全包默认测试、vet 和构建通过。未受改动的部分包使用 Go 测试缓存。
- 全包 race 通过；`ac` 8.364s、`infoextract` 1.366s、`passive/plugins` 34.620s，无已报告数据竞争。
- AC 适配测试覆盖 400 组固定随机任意字节、空词/重复词、第一个原始下标、重叠/后缀、大小写、NUL/非法 UTF-8、nil/零值及并发 `Search`/`Match`。仅承诺每次扫描唯一词集合，不承诺 occurrence 顺序或次数。
- infoextract 保留触发词/fallback、正文/头部路由和规则顺序；验证同词触发多规则、替换/追加、规则和 matcher 快照、并发读写、调用方 `Triggers` 切片隔离及只有空字符串的非空触发词切片语义。规则发布采用 copy-on-write，避免同名替换改写旧读者持有的 backing array。
- Serialization 对照冻结线性实现，比较完整 Result（含 JSON、Artifacts、顺序及截断），覆盖全部文本规则正例、随机字节、URL/form/头部/Base64/二进制、1 MiB/128 surfaces/64 findings、输入截断、64 位候选边界与共享实例并发。冻结表另逐项断言 regex、规则属性、magic 和预算，防止 oracle 拷贝漂移。
- 文本预筛选/字面量替代的短时 fuzz 通过：2 个 worker、40,843 次执行、84 个新增 interesting 输入；这不是全解码管线的 fuzz 或长期流量证明。完整解码管线由确定性对照测试覆盖。
- fingerprint 匹配内核未修改；Registry 不新增统一 AC 策略。Serialization 不改变安全边界，不执行反序列化、联网、解压或解密。
- 集成测试仅编译，未执行本地或外部集成服务。初次命令因默认 Go 构建缓存只读中断，经授权原样重跑成功；未修改全局 Go 配置或迁移缓存以绕过限制。
- 插件性能在上述验证结束后单独测量，结果与原始输出见 [Serialization 性能记录](PERFORMANCE-serialization.md)；不将库级选型数字当作完整插件收益。

## 2026-11-10：AC 库选型对照

工具链 Go 1.26.3 linux/amd64，候选版本、冻结语料、原始输出和复现源码见 [AC 库选型](AC-SELECTION.md)。在独立临时评测模块执行并通过：

```sh
go test -race -v ./...
go test -race -run '^TestVariedEquivalence$' -v -count=1
go test -run '^TestRetainedHeap$' -v -count=1 -cpu=4
go test -run '^$' -bench 'BenchmarkScan|BenchmarkParallelScan|BenchmarkBuild' -benchmem -benchtime=100ms -count=3 -cpu=4
go test -run '^$' -bench '^BenchmarkVaried$' -benchmem -benchtime=100ms -count=3 -cpu=4
```

- Cloudflare TS、Bobu Walk、petar NFA/DFA 与逐词 `bytes.Contains` 在统一关键词集合口径下，通过 120 组固定随机字节/字典、8 goroutine 共享实例以及 JSON/二进制补充对照；race 无已报告竞争。anknown 为 rune API，静态筛除，未将其宣称为实测候选。
- Bobu 稳定版和固定新版分别验证；表格的主要比较使用明确锁定的新版，不把其 API/内存优势冒充稳定标签行为。
- 记录的是合成语料库级基准、构建分配和近似保留堆，不是端到端插件收益、峰值 RSS 或生产流量验收。
- 下载依赖时因默认 Go 模块缓存只读中断，经授权原命令重试成功；只更新临时评测模块，SDK 主模块依赖无差异，复现附件以文本保存，SDK 仍为单一 module。
- 本次未执行第三方内核接入，也没有重跑全仓 `make check` / `make race` / `make integration-compile`；以下早先插件验证结果不得据此解释为当前共享 AC 重构已验证完成。

## 2026-11-10：序列化特征被动插件

工具链为 Go 1.26.3 linux/amd64、Python 3.14.8。最终实现执行并通过：

```sh
go test ./passive/...
go test ./passive/plugins -run '^$' -fuzz '^FuzzSerialization$' -fuzztime=3s -parallel=2
make check
make race
make integration-compile
git diff --check
```

- 新增插件回归覆盖各格式 magic、标准/URL-safe Base64（含短值与 padding 校验）、URL/form 字段、Cookie/JSON 载体、响应降级、普通依赖错误负例、输入只读与输出脱敏，以及扫描/头部预处理/findings 上限和取消。
- `make check` 的文档/仓库检查、17 个 Python 离线测试、50 个字典文件校验、全包测试、vet 和构建通过；全包 race 通过，插件包 15.442s，无已报告数据竞争。
- 短时 fuzz 通过，2 个 worker 执行 24,467 次，未发现崩溃或输出上限断言失败；不替代长期 fuzz 或性能验收。
- 集成测试仅编译，未执行本地或外部集成服务；不将编译结果视为协议或漏洞验证。
- 初次全仓验证因 Go 构建缓存只读而中断，经授权以原命令重跑成功；未修改全局 Go 配置。

检测仅消费合成或已捕获 HTTP 快照，不执行反序列化、解压、解密、探测或跨流关联；格式线索不等于服务端入口或漏洞。使用与边界见 [插件说明](../passive/plugins/README.md)。

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

## 2026-11-07：阶段 3B 实际握手 TLS 控制

工具链：Go 1.26.3 linux/amd64、Python 3.14.8。执行并通过：

```sh
go test -race . ./nethttp -run '^Test(TLSControls|BuildRequestTLS)' -count=5 -timeout=90s
make check && make race && make integration-compile && make integration-local && git diff --check
```

- `make check`：仓库/文档/格式检查、17 个 Python 离线测试、50 个固定字典文件、全包测试/vet/build 通过；根包测试 16.093s。
- `make race`：全包通过，根包 16.943s，无已报告数据竞争。
- `make integration-compile`：集成用例编译通过；`make integration-local`：本地集成真实执行通过，根包 12.226s，明确排除外部 Python Cookie 服务。
- TLS 定向 race 连续 5 次通过；新增控制路径生命周期回归另连续 3 次 race 通过。记录追加后重新检查文档/格式。

本地实际 TLS socket 矩阵覆盖 TLS1.2/1.3 精确范围、H1/H2/严格 H2 的缓冲/流式及 Raw，断言一请求只建一连接、无 DNS/探测握手、实际响应与 TLS 元数据一致；客户端版本上限不能向仅 1.3 服务降级。显式 DNS ServerName 与逻辑 Host 分离，IP 名验证 IP SAN 且不发 SNI；错误 CA/名称、错误 pin 在 HTTP 请求前失败。叶 SPKI hash 与多个候选单独检查，issuer hash 不能冒充 leaf；同主机顺序/并发相反 pin 不串用。

自定义 Profile 内嵌 SNI、缺少 SNI 与 IP 名另有真实握手回归；复核发现 pins-only 情况下内嵌 SNI 可覆盖逻辑验证名，现已在所有非零控制路径协调实际 SNI extension/config，补充真实错误名称与握手状态断言。版本过滤同时收窄 preset bounds 和 SupportedVersions，保留 GREASE/顺序；无交集、重复 supported-version extension、显式 Profile 冲突提前失败。内建 ID 的 nil/占位 SpecFactory 使用依赖一致的内建 preset 后备路径，不 panic 或误报缺失实现。

HTTP CONNECT 验证实际 origin TLS 版本/名称与正确/错误 pin；Raw 仍拒绝代理且不建连接。Do 跨 origin 清除整个 TLSConfig，原始调用方对象不变。新控制下的 TLS/header/body 阻塞、调用方取消 cause、实际 socket 关闭、单槽池回收及 Cookie 逻辑 origin 隔离覆盖 H1/H2/严格 H2。nethttp 输入检查 nil/null/空对象、版本/名称/pin 边界与双向复制。

中间验证中的 Raw CONNECT 正向用例错误假设新增代理支持，改为保留既有拒绝边界并检查零连接；策略单元测试也发现内建 ID 可能携带返回错误的占位 SpecFactory，已修复为与 uTLS 相同的 factory-to-built-in 回退并重跑。最终完整检查没有跳过上述本地回归。

范围限制：不证明 TLS1.0/1.1 在默认 Profile 可用，不承诺改变版本范围后浏览器指纹等价、HTTP/3 或外部代理/目标兼容性；新控制仅 HTTPS 直连/HTTP CONNECT，Raw 仍无代理。显式 DNS ServerName+无 SNI Profile 冲突在 HTTP 应用字节前失败，但可能已经建立 TCP/CONNECT；只有语法、显式 Profile+版本和空版本交集等提前检查保证不拨号。普通/流式使用有界客户端租约，Raw 保留独立 socket 生命周期。未执行外部 Cookie 服务、远端代理、付费服务或性能验收。

## 2026-11-07：阶段四上传、会话、重试与认证

工具链仍为 Go 1.26.3 linux/amd64、Python 3.14.8。执行并通过：

```sh
make check
make race && make integration-compile && make integration-local
git diff --check
```

- `make check`：格式、仓库/文档检查、17个 Python 离线测试、50个固定字典文件校验、全包单测/vet/build 通过；根包16.304s。
- `make race`：全包通过，根包19.337s，无已报告数据竞争。
- `make integration-compile`：所有集成用例编译通过。
- `make integration-local`：本地集成真实执行通过，根包16.230s；明确排除外部 Python Cookie 服务。
- 追加记录后重新执行文档/格式及 whitespace 检查。

定向测试也单独通过：上传与重试 race5轮、普通头部/Raw/上传/重试 race3轮、multipart和nethttp适配 race5轮、会话 race3轮、认证 race3轮。测试仅使用本地受控服务器、内存源和 fake transport。

覆盖要点：

- reader 已知/未知/零长度与短读/前缀限制，H1/H2/严格H2 × buffer/stream 实际发送；取消中断阻塞源、close-once与池单槽恢复，one-shot并发领取/重复使用和预检不消耗源。typed-nil 源/工厂返回值提前报错而非 panic；上传捕获默认关闭，有界前缀且无额外读取。
- 流式 multipart 实际协议矩阵解析、固定 boundary、已知长度精确计算/溢出、未知长度分块、懒打开、多个 part 顺序关闭、生产者/源错误及取消。部分元数据和数量有界，无隐式文件读入或任意正文缓存。
- 会话真实连接复用、共享Engine、Clear/ClearHost、LRU/TTL、port隔离、Secure/Path/Domain/公开后缀/到期/删除、并发清理和在途Set-Cookie再填入。清理/淘汰后的缓存客户端不能继续使用旧jar。
- 状态503重试与 POST显式允许/不可重放抑制、Send/Run默认方法一致、Retry-After裁剪、Total中断退避保留429证据、attempt次数和流式仅一次观察。
- Basic/Digest真实TLS覆盖H1/H2/严格H2、buffer/stream、TLS控制开/关；六种算法与sess/no-qop、stale/挑战上限、有界解析和扩展错误脱敏。上传认证重放精确开关次数、one-shot保留401证据/归还租约、同/跨origin Do清理；第二轮headers阻塞/自定义取消cause保留PhaseError、关闭实际socket并回收池槽。
- 普通头部/framing/URL拒绝发生在打开源之前，Host与URL身份分离，敏感诊断头脱敏；Raw异常字段大小写/重复头和字节原样发送，不受普通规范化或状态重试影响。

中间回归发现 fhttp 即使配置不跟随跳转，仍在307/308的拒绝回调之前提前调用GetBody，多开一次源；现发送给后端的wire副本不暴露GetBody，显式认证/调度/Do保留原始重放能力，相应用例重跑通过。认证网络错误同时遇到context结束时也保留原有PhaseError与取消cause，而非丢失阶段。

范围限制：不执行外部Cookie服务、远端代理/付费API、真实登录或性能验收；不证明跨浏览器SameSite导航语义、Digest rspauth/auth-int/nonce缓存、企业认证或OAuth生命周期。自定义reader/opener/认证扩展必须遵守context与Close契约，SDK不能强制终止不合作的调用方代码；捕获的请求正文可能包含敏感数据，默认不启用。此时阶段五尚未实施。

## 2026-11-07：本地源 IP 与 Linux 网卡绑定

工具链为 Go 1.26.3 linux/amd64、Python 3.14.8。最终实现执行并通过：

```sh
go test -race . ./nethttp -run '^(TestNetworkBinding|TestBuildRequestNetwork)' -count=3 -timeout=90s
make check
make race
make integration-compile
make integration-local
git diff --check
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

- 定向 race 连续三轮通过，根包4.457s、nethttp 1.063s；IPv6 协议矩阵另以 verbose race 连续三轮通过，无 IPv6 环境跳过。
- `make check`：格式、仓库/文档检查、17个 Python 离线测试、50个固定字典文件校验、全包单测/vet/build 通过；根包17.105s。
- `make race`：全包通过，根包23.261s，无已报告数据竞争。
- `make integration-compile`：集成用例编译通过；`make integration-local`：本地集成真实执行通过，根包17.239s，明确排除外部 Python Cookie 服务。
- Windows/Darwin amd64 生产包交叉构建通过；不代表这些平台已运行测试或实测源地址绑定。

实际 socket 证据与边界：

- IPv4 的 `.1` / `.2` 与 IPv6 `::1` 服务端 RemoteAddr 验证，覆盖 H1/H2/严格 H2 × buffer/stream 及 Raw；映射的逻辑 Host/SNI、实际目标和零 DNS 查询保持原语义。
- Linux 独立 SO_BINDTODEVICE 权限探针成功，实际请求 TCP fd 的 getsockopt 读回 `lo`；设备 TLS 矩阵、设备/未绑定设备策略分池与同策略复用均真实执行，当前进程没有权限跳过。
- 不同源分池、mapped 等价源复用、16路混合并发、重定向复制与调用方不可变性；取消/响应头阶段超时后实际 socket 关闭、单槽池恢复。
- stale H2 的 bound-tls-phase buffer/stream 模式 race 三轮通过，监听端同时检查 warm 与实际重连 socket 的 `.2` 源；完整 stale H2 回归也 race 三轮通过，保留当前租约 TLS 预算、零 DNS 和关闭断言。
- 地址/设备语法、源地址族冲突、候选筛族与永久失败立即停止；非本机源与不存在设备都不能到达 HTTP handler，不回退未绑定连接。不可用源保留与独立 bind 探针一致的内核 errno 和 net.OpError，Observer 只报告一次且 WillRetry=false；失败后槽位仍可使用。
- 无效绑定及代理组合在打开上传源前拒绝；结构化 JSON 的零值/null/类型、平台拒绝与深拷贝一致，不把解析成功当作 socket 能力证据。

中间 IPv6 Raw 回归因测试 fixture 未设置 Raw 私有 noGuard 而正确被生产地址保护拒绝；补齐仅受控本机测试的配置后通过，生产拨号保护未放宽。独立只读复核未发现运行路径、池身份或文档边界不一致。

范围限制：仅绑定直连目标 TCP，不绑定 DNS resolver，不支持代理组合或源端口选择；不提权、不配置系统接口/路由、不监控或动态迁移已有 socket。当前环境允许 SO_BINDTODEVICE，未在另一个无权限进程中实测 EPERM/EACCES；接口重命名/删除/同名重建及 NAT 的持续行为仍由内核决定，不作跨环境保证。未执行远端目标/代理、外部 Cookie 服务或性能验收；测试中的环境跳过必须单列，不能视为验证通过。完整契约见 [绑定指南](NETWORK-BINDING.md)。

## 2026-11-14：HTTP 错误分类与单行展示

工具链 Go 1.26.3 linux/amd64、Python 3.14.8。默认 `GOCACHE` 在当前只读环境下不可写，以下 Go 命令显式使用可写的 `/tmp/netloom-gocache`，未修改全局 Go 配置。执行并通过：

```sh
GOCACHE=/tmp/netloom-gocache go test -race . -run '^(TestClassify|TestMessage)' -count=5
GOCACHE=/tmp/netloom-gocache make check
GOCACHE=/tmp/netloom-gocache make race
GOCACHE=/tmp/netloom-gocache make integration-compile
GOCACHE=/tmp/netloom-gocache GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOCACHE=/tmp/netloom-gocache GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build ./...
git diff --check
```

- 新分类/展示测试以 race 连续 5 轮通过（根包 1.931s）。
- `make check`：格式、仓库/文档检查、19 个 Python 离线测试、50 个固定字典文件校验、全包默认测试、vet 和 build 通过；根包 18.840s，追加本记录后复跑为 16.983s。
- `make race`：全包通过，根包 21.943s，无已报告数据竞争。
- `make integration-compile`：所有带 integration tag 的测试编译通过。
- Windows/Darwin amd64 生产包交叉构建通过；只证明编译，不代表这些平台已运行测试。
- Go 命令输出过模块缓存 stat 写入只读的提示；模块内容读取和构建/测试结果不受影响，改用可写 `GOCACHE` 后其余步骤正常完成。

覆盖要点：本地 `httptest`、真实监听器、失败 resolver 与可控拨号覆盖 DNS 失败、拒绝连接、连接超时、证书不可信、TLS 握手失败、response_header 超时、正文空闲超时、正文读取中断、`*net/http.MaxBytesError`、重定向超限、地址阻断、非法代理和已关闭 Engine；断言 `Classify` 的 kind/phase/timeout 与优先级，以及 `Message` 单行、无 `netloom: ` 前缀、保留 Phase、不回显代理凭据。另检查 nil、普通未证明错误、调用方取消不被猜测成 body/TLS 失败、多行/包装 sentinel 的清理。既有全包测试和 race 同时通过，`Error()` 文本、sentinel、`Timeout()` 与 `errors.Is/As` 未改动。

范围限制：内建缓冲正文超过 `MaxBodySize` 仍是截断加 `Response.BodyTruncated`，不是 error，因此 `body_limit` 只覆盖错误链中实际出现的 `*net/http.MaxBytesError`（例如自定义 transport），没有为截断新增运行时错误。分类依赖错误链中的类型/sentinel 证据；未证明的 connect/request/header 非超时失败仍为 `unknown`。未执行外部目标/代理、外部 Cookie 服务或性能验收。
