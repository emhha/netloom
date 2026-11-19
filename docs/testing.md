# 测试说明

## 默认测试

```sh
go test ./...
go vet ./...
go build ./...
```

默认测试不要求真实数据源凭据或付费查询，但部分传输、代理、HTTP 会话和 GeoIP 更新用例会启动本地可控 HTTP/TLS 服务，因此需要允许本机 TCP socket。Go module 依赖首次构建前也需要准备齐全。数据源的 fake client/凭据读取器测试验证本地契约，不代表已验证真实第三方服务。

`fingerprint` 使用仓库随附规则做离线加载、等价性和匹配测试；不主动扫描外网。字典测试使用固定快照，不应联网更新。

## HTTP 流量分析回归

```sh
go test -race ./traffic -count=5
```

本地 TLS 源站与两个 CONNECT 代理检查主动发送和解密式 MITM 共用代理、单次请求覆盖、压缩字节转发，以及主动请求在接入分析前后的 TLS 版本、密码套件和 ALPN。合成 JS 检查跨入口去重命中不重发旧发现、正文长度变更后重新分析，以及流式和 Run 路径的单次报告。离线缓存用例另外覆盖等长变化、截断长度未知和显式启用正文哈希。队列回归故意阻塞回调，检查超限时仍原样读取并可计数丢弃。用例只使用本机服务，不验证外部代理、浏览器指纹完全等价或真实目标的风控行为。

完整调用示例用 `go run ./examples/traffic`，本机运行并显示两个入口的报告。独立运行 MITM 压力基准与解读指标，见 [流量性能记录](PERFORMANCE-traffic.md)。

`go test ./mitm -run '^TestHTTPSConnectReusesTunnelWithLiveUpstreamContext$'` 验证真实客户端在一条 CONNECT 隧道内连续发送三次 HTTPS 请求，上游转发 context 在后续请求上仍可用。

## 代理失败关闭回归

```sh
go test -race . ./httpclient ./nethttp ./internal/proxyconfig -run 'Proxy|CurlUnsupported|TestParse$' -count=10
```

纯解析测试覆盖空值直连、空白/缺 host/无效端口/路径/query/fragment 拒绝、各包支持的 scheme、凭据和 IPv6。入口测试检查无效代理不消耗准入/源限流、不发送、不打开重放正文、不修改 User-Agent，不回显凭据、不累计目标失败；Mutators 能修复或制造配置错误。有效 HTTP 代理另用本地服务检查实际转发与认证。HTTPS/SOCKS 的解析和客户端构造通过不代表这些外部代理端到端成功，也不等同于实时取消保证；HTTP CONNECT 取消由本地代理回归覆盖。

## API 凭据与重试回归

```sh
go test -race ./mapping ./enterprise ./httpclient
```

凭据测试注入 fake reader/client，验证缺失与存储错误、取消/deadline 错误链、同时返回值和错误时优先报错，以及读取失败零 HTTP 调用。FOFA 分页固定同次 key/email、下次查询轮换；三个测绘引擎验证 trim/轮换及仅需 Get 或 Post 的窄接口，爱企查检查五个公开方法、Cookie 修剪和不支持字段的既有验证顺序。会话的 fake RoundTripper 检查默认安全方法、POST 显式允许、nil/空/无效方法列表、配置副本、一次性正文不重试、最终响应体归属与网络耗尽错误链。测试不请求真实付费 API，不证明 exactly-once 或账户计费策略。

## HTTP 可靠性回归

```sh
go test . -run '^Test(Reliability|PartialResponse)' -count=1
```

这些默认测试使用 fake transport 或本地可控 HTTP/TLS 服务，覆盖请求/配置/context 超时（含正文阻塞与亚毫秒期限）、失败时的部分响应、重试后证据保留、实际 TLS 连接次数与证书、流式 EOF/提前关闭/读取失败状态，以及 Engine.Close 中断读取。它们不访问外网，不替代真实代理/外部目标验收。流式状态并发读取和关闭路径同时由 race 检查。

## 连接池与 HTTP/2 回归

```sh
go test -race . ./nethttp -run 'Test(ConnectionPool|ClientDialScope|HTTP|BuildRequest)' -count=5
```

本地服务覆盖 H1/H2 缓冲与流式顺序复用、实际 IP/证书/缺失阶段 timings、默认不复用与按次 FreshConnection、origin/验证开关/代理超时隔离、自定义 Profile/信任根一次性使用、客户端容量/空闲 LRU/TTL、等待取消、EOF 租约所有权、失败释放、Cookie 会话与客户端驱逐的独立生命周期，以及 Engine.Close 实际关闭空闲 socket。严格 H2 用例检查 ALPN 失败前无 HTTP/1 请求，含明文/无 ALPN/H1-only 目标、自定义信任/mTLS 和代理/取消；HTTP CONNECT 用例验证早期限/显式取消/Engine.Close 后 socket 关闭、认证不泄漏、响应头上限及预读字节保留。过期 H2 重连用例先完成真实 H2 请求、断开旧连接，再阻塞新 TLS 握手，检查缓冲/流式的超时、取消和 Close 不因依赖的后台 context 而卡住。ClientDialScope 另测旧 lease 取消不误关空闲连接及过时 dial 不可归入新 lease。这些不是外部网络或性能验收。

## 阶段超时与结构化错误回归

```sh
go test -race . ./nethttp -run 'Test(Phase|BuildRequestPhase|ConnectionPoolStaleHTTP2|HTTPProxyCONNECT)' -count=5
```

本地 H1/H2/严格 H2 覆盖 POST 后完整响应头超时、103/不完整最终响应头、部分正文 idle 失败与流式 Status、调用方暂停消费不误计 idle、持续进展的正文不被固定 body 时长截断、TLS stall（含大写 HTTPS scheme）、真实过期 H2 重新握手、CONNECT 阻塞后的 socket 关闭与池容量释放。另测连接复用不重新计算 TLS 预算、晚到 WroteRequest 不复活已结束的 header timer、整组策略继承/显式零覆盖、负值和毫秒换算溢出、调用方提前 deadline/取消 cause、Raw TLS/header/body/部分响应，以及 Total 跨重试和 Do 多跳不重置。Connect 的模拟拨号用例检查依赖 Background context 被当前 lease ctx 替换；真实 socket 取消由 TLS/CONNECT 用例检查，不依赖不可控外网黑洞地址。这不是精确 TLS 握手时长、外部代理、浏览器等价性或性能验收。

## 错误分类与展示回归

```sh
go test -race . -run '^(TestClassify|TestMessage)' -count=5
```

本地 `httptest`、真实监听器和可控拨号覆盖 DNS 失败、拒绝连接、连接超时、证书不可信、TLS 握手失败、响应头超时、正文空闲超时、正文读取中断、`*net/http.MaxBytesError` 大小限制、重定向超限、地址阻断、非法代理与 Engine 已关闭。断言 `Classify` 的 kind/phase/timeout，以及 `Message` 单行、无库名前缀、无凭据；分类只用类型/sentinel 证据，不按文本猜测。内建正文上限仍表现为截断而非错误，因此大小限制用例检查可分类的 `*http.MaxBytesError` 链。

## 直连映射与地址族回归

```sh
go test -race . ./nethttp -run 'Test(Network|BuildRequestNetwork|ConnectionPoolStaleHTTP2)' -count=5 -timeout=90s
```

默认本地测试覆盖规则边界/重复/规范化、完整策略池身份、原始 Host/SNI/证书验证名（H1/H2/严格 H2、缓冲/流式/Raw）、逐跳映射及跨 origin 凭据清理。受控本机 UDP DNS 与模拟最终 literal 拨号检查生产保护开启时的地址族筛选；不向文档专用 IP 建立真实连接。明确映射用 fail-on-DNS resolver 检查不回退解析/CNAME，无候选或 tcp family 冲突不跨族回退；共享 context 预算不被每候选重置。负向用例检查受阻最终地址、规范等价的逻辑 IP 在池前拦截、任何非零策略与代理拒绝，以及跳过受阻邻居不禁止允许地址重试。真实过期 H2 握手增加映射逻辑主机且禁止 DNS 的场景，检查当前租约映射和取消仍生效；这些不证明远端 DNS、代理映射、Happy Eyeballs 或吞吐性能。

## TLS 控制回归

```sh
go test -race . ./nethttp -run '^Test(TLSControls|BuildRequestTLS)' -count=5 -timeout=90s
```

真实本地服务检查 TLS1.2/1.3 精确范围、H1/H2/严格 H2 的缓冲/流式与 Raw 只发生一次实际连接；版本无交集在拨号前失败，版本上限不能向仅 1.3 服务回退。显式 DNS SNI 与逻辑 Host 分离，IP 验证保留 IP SAN 身份但不发 SNI；自定义 Profile 内嵌/缺少 SNI 的覆盖与冲突另测，pins-only 不能将验证名偷换成 Profile 内嵌值。pin 的匹配/失败、正常 PKI 名称/CA 验证、叶而非 issuer hash、多个候选、同主机顺序/并发 pin 隔离，以及失败前无 HTTP 应用请求均有断言。HTTP CONNECT 作用于 origin TLS 而非代理，Raw 代理拒绝且不拨号；Do 跨 origin 清除 TLSConfig、保留调用方对象。非零控制的 TLS/header/body stall 与 caller cause 检查实际 socket 关闭、阶段错误和单槽池恢复；Cookie 仍按逻辑 URL 而非 ServerName 隔离。结构化输入测试省略/null/空对象、版本/名称/pin 语法和双向复制；不执行外部代理、TLS1.0/1.1 或浏览器指纹等价性验收。

## 并发检查

```sh
go test -race ./...
```

需要支持 race 的 Go 工具链、CGO 和 C 编译器。涉及 Engine 关闭、调度、缓存、流式响应、Cookie 或 GeoIP reload 的修改应运行相关包的 race 测试；重命名或依赖调整后建议全包执行。

## 调度与主机状态回归

```sh
go test -race . -run '^Test(EngineLifecycleRegression|HostSemaphore|EngineSendReleasesDistinctHostState|SchedulerHostErrorHistoryIsRunScoped)' -count=10 -timeout=180s
```

使用注入 transport 和 channel 屏障覆盖 Run/Submit/Close 启动竞争、single-flight、取消与背压、多个 Close 等待在途退出及结果通道关闭；同主机等待者不能被状态回收拆成两套配额，取消等待者释放引用，大量不同主机 Send 后无空闲槽残留，成功重置及 Run 结束释放错误历史，Run 内跳过仍 sticky。重复竞争加 race 不等于证明全部线程交错；这些不是外部代理、吞吐或全扫描内存上限验收。

## 目录扫描并发回归

```sh
go test -race ./dirscan -count=5
```

通过 fake engine 与 channel 屏障验证实际重叠、并发上限、慢队首下的有界重排、按派发顺序去重、取消/deadline 后等待在途退出与部分结果保留、错误阈值、Crawl/递归边界及正文计数过滤；不依赖外部目标，也不关闭生产拨号保护。测试证明 worker/协调器契约，不证明真实网络同主机吞吐或性能收益。配置与并发压力变化见 [目录扫描](../dirscan/README.md)。

## 集成测试

```sh
# 只验证所有带 integration tag 的测试能够编译
go test -tags=integration ./... -run '^$'

# 执行本地集成测试，明确排除外部 Cookie 服务
make integration-local

# 全量执行；先确认以下环境条件
go test -tags=integration ./...
```

根包的 TLS/mTLS、代理和流关闭集成测试使用本地服务。Python Cookie 测试需要单独准备受控服务：端口 9099、测试要求的 Cookie/跳转响应，以及 probe 包使用的 `cookie.test` / `other.test` DNS 映射。仓库不提供该服务的启动程序，具体协议以测试断言为准。

没有准备服务时 Cookie 用例会跳过，不能把 `go test` 的成功退出当作这些场景的执行证据。不要为了让 probe 用例通过而关闭生产拨号防护或自动修改 `/etc/hosts`。调用方应按测试中描述的协议准备受控服务，再运行对应测试。CI 执行集成编译与 `integration-local`：后者明确排除名为 `TestPythonCookieServerE2E` 的两个外部服务用例，不假称执行过外部 Cookie 服务。本地 TLS/代理/流关闭集成仍会真实运行。

## 本地源 IP 与 Linux 网卡绑定

```sh
go test -race . ./nethttp -run '^(TestNetworkBinding|TestBuildRequestNetwork)' -count=3 -v -timeout=90s
go test -race . -run '^TestConnectionPoolStaleHTTP2ReconnectCancellation$' -count=3 -timeout=45s
```

这些测试只创建受控本地 socket，不改接口/路由、不提权、不依赖外部服务器。服务端 RemoteAddr 验证真实 IPv4/IPv6 源，覆盖 H1/H2/严格 H2、buffer/stream 和 Raw；Linux 用独立内核探针验证 SO_BINDTODEVICE 权限，并从实际请求 socket 读回设备名，检查池隔离、映射、取消与 stale H2 重连。不可用源/设备不得回退，永久绑定错误不能被重试策略重发，预检不打开上传源。

基础 `127.0.0.1` 和 `::1` 源测试不依赖 Linux；`.2` loopback alias 的矩阵在非 Linux 明确跳过。IPv6 本地地址族不可用、Linux 设备绑定探针返回 EPERM/EACCES，或系统允许任意未配置源地址时，相应测试会明确说明缺失覆盖，不能将跳过视为能力验收。非 Linux 的 Interface 拒绝由平台分支验证，跨平台 build 只证明编译、不证明该平台运行行为；权限说明见 [绑定指南](NETWORK-BINDING.md)。

## 仓库与资源检查

```sh
python3 scripts/check-repository.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/update-dirsearch-wordlists.py --check
```

仓库检查覆盖维护中文档的相对链接、Go 模块/包命名、旧导入残留、包布局及格式。上游 README、许可证和第三方原始资源不是品牌替换或文档链接修复目标。字典更新脚本的测试只在临时 Git 仓库中操作，不改动外部仓库。

## 验证结果的记录方式

在 [验证记录](VALIDATION.md) 中追加日期、工具链、实际命令、结果及限制；不要覆盖旧日期的环境证据。测试失败先区分实现失败、依赖准备失败和环境限制。确需跳过时写出精确命令与缺失覆盖，不在默认入口永久跳过失败用例。

真实 MMDB 查询需要调用方合法提供数据库；单元测试的生命周期和错误路径不能替代真实数据库内容验收。真实数据源认证、配额与收费接口也不属于默认测试，需单独获得授权。

性能基准单独执行，避免与 race/全量测试争抢资源；命令和历史测量见 [指纹性能记录](PERFORMANCE.md)。
