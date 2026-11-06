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

根包 Request.VerifyTLS 默认 false；调用方应显式选择。自定义根和客户端证书不改变该开关。
Send 对非 GET/HEAD/OPTIONS 方法禁用重试；Run 使用任务调度器的重试策略，调用方应对具有副作用的任务设置 Retries=-1。
耗时与 TLS 字段是可选观测，不能把缺失字段当作零耗时。流式路径使用原生 trace，不另行握手；缓冲路径在部分 HTTP/1.1 TLS 元数据缺失时会尝试第二次握手。
SendStream 不重试且不截断正文；其请求级 Timeout 默认由底层传输补 10 秒，Config.Timeout 不覆盖流式路径。
Raw 不使用 CookieJar；Raw+Proxy 目前明确报错，防止悄悄绕过代理直连。普通和流式路径支持 tls-client 的代理配置。

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

Engine.Close 幂等，阻止新工作，取消已有请求及队列、关闭活动流，并等待工作退出。
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
