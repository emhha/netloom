# API 与配置

## 核心契约

```go
func New(Config, ...EngineOption) (*Engine, error)
func (*Engine) Send(context.Context, *Request) (*Response, error)
func (*Engine) SendStream(context.Context, *Request) (*StreamResponse, error)
func (*Engine) Run(context.Context, []Task) (<-chan *Result, error)
func (*Engine) Submit(Task) bool
func (*Engine) Schedule(Task)
func (*Engine) Close() error
```

`Transport.RoundTrip(context.Context, *Request) (*Response, error)` 是底层契约。
`Runtime` 提供 Send/Schedule 两个方法。Request/Response 的 Header 使用 fhttp.Header。
`Do(ctx, sender, request, RedirectPolicy)` 显式控制重定向；Send/SendStream 本身不自动跟随跳转。
`ParseTLSOptions(caPEM, certificatePEM, keyPEM string)` 只解析调用方传入的内存凭据。
`nethttp.ParseCurl` 不启动 shell、不读文件；`nethttp.BuildRequest` 进行有界请求转换。
RequestInput 的 FollowRedirects/MaxRedirects、Stream、MaxResponseBytes 是调用方执行提示，不由 BuildRequest 执行；核心正文上限由 Config.MaxBodySize 控制。

## 配置与已有语义

| Config 字段 | 零值/默认行为 |
| --- | --- |
| Threads | 50 |
| MaxConcurrentPerHost | 10 |
| RatePerSecond | 150，非正数会补默认值 |
| RatePerMinute | 0 不限，与秒级限流同时生效 |
| Delay | 0；请求开始前额外延迟 |
| Retries | 0 补 2，负数禁用；网络错误可重试，HTTP 错误状态不重试 |
| MaxHostErrors | 30，Run 的主机错误阈值 |
| Timeout | 10 秒 |
| MaxBodySize | 2 MiB，缓冲响应上限 |
| CookieJar | false；开启后按主机隔离并共享 |
| ConnectionPool | nil；保留每次尝试新建客户端。非 nil 显式启用有界复用，见下文 |

根包 Request.VerifyTLS 默认 false；调用方应显式选择。自定义根和客户端证书不改变该开关。
Send 对非 GET/HEAD/OPTIONS 方法禁用重试；Run 使用任务调度器的重试策略，调用方应对具有副作用的任务设置 Retries=-1。
Send、Run、SendStream 的有效总超时均为：正值 Request.Timeout 优先，否则使用 Config.Timeout（配置缺省 10 秒）；更早的调用方 context deadline 始终有效。超时覆盖单次尝试的建连至正文读取，不包含 Engine 等待并发槽/限流的时间；调用方需要包括排队、重试及重定向的总预算时应设置 context deadline。TCP 拨号超时仍固定 10 秒，不等于总超时上限。直接 Transport.RoundTrip 没有 Engine 配置，Request.Timeout 缺省为 10 秒。不修改调用方 Request。
SendStream 不重试且不截断正文；有效总超时也覆盖返回响应头之后的正文读取。

### HTTP 协议策略

`Request.HTTPVersion`（以及 `nethttp.RequestInput.HTTPVersion`）支持：

| 值 | 行为 |
| --- | --- |
| 空或 `auto` | 保留浏览器 Profile 的 HTTPS ALPN 协商，可使用 H2，允许 HTTP/1.1；关闭 HTTP/3 |
| `1.1` | 强制 HTTP/1.1 |
| `2` | 偏好 H2、允许 HTTP/1.1 降级；与 `auto` 一样保留 Profile 的 ALPN，不强行改写不支持 H2 的自定义 Profile |
| `2-only` | 仅 HTTPS；必须在同一实际连接的 TLS 握手中协商 `h2`，否则在发送 HTTP 请求之前失败；不支持明文 h2c |

严格模式不先发送 HTTP/1.1 请求或额外探测握手；正常 TLS 验证、内存 mTLS 和取消语义仍生效。当前 `2-only` 仅支持直连及 `http://` CONNECT 代理（含 Basic 代理认证），HTTPS/SOCKS 等其他代理 scheme 显式报错，不悄悄直连。明文 URL 或成功握手却没有协商 H2 时可用 `errors.Is(err, ErrHTTP2Unavailable)` 判断；拨号、TLS 验证、握手和 context 错误保留自身原因，不一律替换成协议错误。其他版本值返回参数错误。Raw 字节路径不应用这些协议策略；设置 `HTTPVersion` 不会改写 Raw。

### 有界连接复用（显式启用）

```go
engine, err := netloom.New(netloom.Config{
    ConnectionPool: &netloom.ConnectionPoolConfig{
        MaxClients:  32,
        IdleTimeout: 30 * time.Second,
    },
})
```

- `ConnectionPool=nil` 保持原来的每次尝试新客户端、用完关闭行为；非 nil 配置中 MaxClients=0 默认 64，IdleTimeout=0 默认 30 秒，负值令 New 返回错误。New 复制配置，后续修改原配置不影响 Engine。
- 每个 Engine 独立管理池。MaxClients 同时约束活跃、空闲、创建中的客户端和不可缓存的一次性租约；仅驱逐空闲 LRU 项，全部忙时等待租约或 context 结束，不绕过容量上限创建临时客户端。此等待包含在单次 Request.Timeout、HeadersMS/TotalMS 内，而不是并发槽/限流的 QueueMS。原有 Threads/MaxConcurrentPerHost 限制仍生效。
- 客户端独占租约持续到 Body 关闭，H1/H2 可顺序复用连接；暂不支持同一客户端并发 H2 multiplexing。MaxClients 是客户端/租约上限，不是对第三方后端所有瞬时 TCP socket 数的严格承诺。每个客户端只绑定一个精确 scheme+URL.Host，避免其内部跨 origin 缓存无界增长；隐式/显式默认端口可能分成不同项。
- 缓存还按代理 URL（含认证）、代理有效毫秒超时、VerifyTLS 和协议策略隔离。直连超时由每次 context 管理，不因 Request.Timeout 不同拆池；`auto`、空值和 `2` 可共享相同配置。Header、正文不进入 key，按每次请求发送；不记录/导出含凭据的内部 key。
- 首版只缓存没有显式 Profile、TLSConfig=nil，且直连或使用 `http://` 代理的请求。其他代理 scheme 使用一次性租约，不缓存第三方后端的 H2 重连状态。nethttp.BuildRequest 的空 TLSProfile 保留零 Profile，使用 Engine 的默认快照；非空名称会显式选择 Profile，因此走一次性租约。默认 Profile 在传输初始化时复制集合并固定；显式/自定义 Profile、任意非 nil TLSConfig（含自定义信任根或 mTLS）和 `2-only` 使用同一容量约束下的一次性租约，不依据不完整的指纹标签、证书指针或私钥散列复用。Profile 的工厂/闭包及调用方提供的 TLS 对象仍必须保持不可变，禁止并发修改。
- `Request.FreshConnection=true`（输入适配器同名字段）禁止该次尝试借用空闲客户端，并在完成后关闭；仍受容量、代理和拨号安全策略约束，不清空其他请求的空闲池。
- IdleTimeout 用于后端空闲 socket 回收及下次获取时的过期条目清理；不启动后台清理服务。成功且完整采集的缓冲请求、观察 EOF 后正常 Close 的流可归还缓存；正文截断、读取失败和流提前关闭会丢弃客户端。EOF 后必须 Close 才归还租约，取消/context 到期或 Engine.Close 也会释放租约。
- CookieJar 保留原来的 host（含显式端口）会话隔离；LRU 驱逐客户端不会清空 Cookie。Cookie jar 存储与客户端池独立，目前没有独立容量限制，不能将 MaxClients 当作全部会话内存上限。Raw 不使用此池。
- 直连及 HTTP CONNECT 的底层连接按当前独占租约绑定 context，覆盖第三方 H2 后台重连的 TCP/TLS/初始化；请求结束成功归还前解除旧取消回调，避免一次请求取消误关后续租约。过期 H2 连接重拨不会获得脱离请求预算的后台握手。
- 复用响应仍从实际连接读取 TLS/IP，不复制上次的 DNS/Connect/TLS timings；复用时没有发生的阶段保持 nil。代理路径不将代理 TCP peer 冒充目标出口 IP。

### 失败与部分响应

Send/Transport.RoundTrip 可同时返回非 nil Response 和非 nil error。状态码、headers 和已读正文仍是有效的部分证据，不能因 error 丢弃，也不能将它视为完整成功。BodyTruncated 仅表示大小上限导致的主动截断；读取失败由 error/Response.Error 表示。
重试失败保留最近一次非 nil 响应，返回的 error 是最终失败原因，两者可能来自不同尝试；本阶段不提供逐次尝试历史。Run 失败时同样保留证据，并将最终错误写入 Response.Error，不执行成功分析 Pipeline。重定向 Do 也会保留发送方返回的部分响应。

### 实际连接诊断

普通缓冲与流式路径使用实际请求的 trace/TLS 状态，不为补充元数据另行握手。TLS 和 DNS/Connect/TLS/FirstByte 阶段测量可能缺失（nil），尤其是自定义 TLS 或代理路径；不能将缺失解释成零耗时，也不伪造代理出口 IP。Raw 路径保留自身的 ResponseTime/TLS 信息，尚未提供同等 Timings。
缓冲 Response.Timings 的 HeadersMS 从传输开始计至收到响应头，BodyMS 为有界采集耗时，TotalMS 为这两者之和，不包含重试/跳转或后续 CNAME 补充查询。缓冲路径 QueueMS 暂不测量，保留零值。流式 Response 是响应头时的固定元数据，其 BodyMS/TotalMS 尚未完成；完成后的测量使用 StreamResponse.Status()，不要等待 Response 被后台更新。

StreamResponse.Status() 返回线程安全、可独立修改的 StreamStatus 快照：

- BytesRead 是调用方经 Body.Read 收到的正文 bytes，不是网络线上传输量；不自动记录正文。
- Complete 仅在读到 EOF 时为 true。即使读了声明的 Content-Length，未观察到 EOF 也不声称完成。
- Finished 在 EOF、读取错误或关闭时置位；BodyMS/TotalMS 此时冻结，之前为零。流式 QueueMS 单独记录并发槽/限流等待，不计入 TotalMS。
- Closed 表示 Body 已关闭；Error 记录读取失败、上下文取消，或提前 Close 的 ErrStreamClosedEarly。读取到 EOF 后正常 Close 不改写完成状态；Close 本身仍返回底层关闭错误。
- Status 可与单个读取者及 Close 并发调用，不允许多个 goroutine 同时读取 Body。EOF 不释放并发槽，仍须显式 Close。
Raw 不使用 CookieJar；Raw+Proxy 目前明确报错，防止悄悄绕过代理直连。普通和流式的非严格协议模式保留 tls-client 的代理 scheme 支持。HTTP CONNECT 交换使用自有 context-aware 拨号器：取消同时关闭进行中的代理 socket，CONNECT 响应头上限 64 KiB，代理 URL 禁止非根路径/query/fragment，认证只发往代理。HTTPS/SOCKS 等其他 scheme 仍依赖第三方拨号器，其连接/代理握手部分可能只遵守固定正值超时而非实时 context 取消；尚不宣称这些路径与 HTTP CONNECT 有同等取消保证。

## 所有权、背压与关闭

Send 将正文读入内存并关闭底层 Body；BodyTruncated 标明主动截断。
SendStream 的调用方必须关闭 Body，即使已读到 EOF；Close 幂等并释放并发槽和连接。取消请求上下文或关闭 Engine 也会关闭活动流。
结果快照在交给分析器后由调用方保证不再修改；netloomdata 转换复制正文、Header 和所需 TLS 字段。
不要在并发发送期间修改 Request、TLSOptions、Config 或规则输入。

一个 Engine 同时只接受一个 Run，重复调用返回 ErrEngineBusy。
Run 返回有界结果通道；消费者须持续读取或取消上下文。Submit 队列满、未运行或已关闭时返回 false；Schedule 丢弃该布尔值。
派生任务使用 Context.TryEmit 处理背压，或 Emit 将拒绝转为 ErrQueueFull；工作线程不会阻塞等待自己的队列。
Context.Next 支持嵌套的前后处理；当前实现也会继续执行未显式 Next 的后续处理器。要终止必须 Abort。
Run 和独立 Send 的限流器分别计数；并非跨所有入口的统一速率配额。

Engine.Close 幂等，阻止新工作，取消已有请求及队列、关闭活动流，唤醒租约等待者，并在工作退出后关闭池内空闲连接。
请勿在本 Engine 的 Pipeline 处理器内调用 Close；应取消上下文，由拥有 Engine 的外层关闭。
自定义处理器若忽略上下文并永久阻塞，Close 同样会等待它退出。

## API 查询包

httpclient 是独立的标准库 HTTP 会话，不能套用根包的零值配置、TLS 指纹或拨号防护。mapping 与 enterprise 使用调用方提供的凭据读取接口，不内置数据库或密钥服务。重试可能产生重复付费请求，须由调用方明确选择。

包级配置、响应体所有权、限流与限制分别见 [httpclient](../httpclient/README.md)、[mapping](../mapping/README.md) 和 [enterprise](../enterprise/README.md)。

## 扩展契约

离线 fingerprint、infoextract、passive 仅依赖 httpdata；不需要创建 Engine。
指纹推荐通过 Config.RulesDir 显式指定规则目录并加载 sources.json，当前禁用 webfinger、启用 EHole/FingerprintHub/Wappalyzer。配置模式对启用文件的缺失、空文件、无效原生格式返回错误；不与逐文件字段混用。

保留 WebfingerYAML、CustomRulesDir、WappalyzerJSONPath，新增 EHoleJSONPath、FingerprintHubJSONPath 作为独立显式输入，不读取 sources.json。旧 YAML/Wappalyzer 输入保持原有缺失文件降级语义；两个新原生 JSON 输入返回加载错误。零值配置不读文件。规则来源与格式细节见 [规则说明](../fingerprint/rules/README.md)。

MatchExchange(ctx, *httpdata.Request, *httpdata.Response) 额外校验 FingerprintHub 原生探针方法、路径和请求头，并支持已抓取 POST 响应。Match(ctx, response) 保留兼容；没有请求上下文时只评估普通 GET、通用首页探针。Response.URL 可约束路径，Response.FaviconMD5 和原 FaviconHash 作为调用方已捕获图标的证据。内置 passive 指纹插件已传入请求上下文，缓存键覆盖图标 MD5 与正文截断状态。

EHole/FingerprintHub 的 AC、图标及正则字面量索引在 New 时构建，Engine 可并发复用。正文转换和请求约束缓存均限于单次调用，不共享可变匹配状态。优化不改变条件、结果顺序、版本或置信度；缺少可证明必要的字面量时会退回完整正则检查。详见 [性能记录](PERFORMANCE.md)。

webfinger.go 提供独立 WebfingerMatcher、LoadWebfingerYAML 与 Len（包含仅图标规则的去重技术数），和其他来源保持同类入口结构。Engine 不再持有 webfinger 的 AST/AC/图标内部状态；底层 lexer/parser/ast/compiler 继续独立组织。默认来源开关保持不变。
infoextract 默认仅加载高敏感凭据类规则，可 AddRule 显式扩展；邮箱、内网 IP、linkfinder 等不属于当前内置规则。passive.New 显式选择插件与内存缓存容量。

probe.Run 返回结果通道，dirscan.Run 返回结果切片。调用方负责目标授权；无数据库或任务服务。
BuildWordlist 优先使用 Config.Wordlist；其他预设需 WordlistDir，目录结构沿用 categories、custom、dicc.txt。
LoadWordlist(base, path) 支持显式文件或 CATEGORY: 名称；LoadFrameworkByFingerprint(base, labels) 使用显式基目录。
不再提供会创建用户文件的 InitWordlistDir。

仓库附带的固定版本 dirsearch 字典位于 dirscan/wordlists/dirsearch/db；显式将其配置为 WordlistDir 才会加载。版本、许可证和更新方式见该目录上层的 README.md。其他应用部署时自行提供可用的资源路径。

mitm.NewAuthority 可接收 AuthorityOptions{CommonName, CacheCapacity}；默认名称 netloom MITM CA、缓存 256。
LoadAuthority 显式接收 PEM；PEM 返回副本，不自行存储。
mitm.New(authority, backend, Options{Username, Password, Realm}) 返回 http.Handler，认证参数由调用方提供，空用户名禁用认证。
Backend 提供 CheckTarget 和 RoundTrip；转发证书与目标策略由 Backend 决定。Proxy.Close 关闭 CONNECT 连接；HTTP Server 生命周期由调用方管理。
ObserveBody 在 Close 时回调有界证据及截断状态，必须提供非 nil 回调。证据回调、私钥持久化和审计均属调用方责任。

geoip.New(dataDir, ...Option) 显式选择数据目录，Init(ctx) 只读本地 City/ASN/Country MMDB 或 CDN JSON；无资源返回 ErrNoData。Lookup/LookupBatch 保留 IPInfo 模型；Close 幂等并保护并发读取。Update(ctx, ...DataSource) 才会下载，必须提供文件名及 URL；可 WithHTTPClient 指定网络策略。无隐式用户目录或七天更新行为，详见 [GeoIP 说明](../geoip/README.md)。
