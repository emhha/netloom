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

### 调度与主机状态生命周期

`Run` 仍为 single-flight，`Submit` 仍为非阻塞接纳，队满、已取消、关闭或无活动 Run 时返回 false。调度器的运行 context、worker 和种子 feeder 保活计数在发布前完成初始化，运行期间不替换 context。`Close` 先拒绝新工作、取消并等待活动 Send/流/Run；Run 的 worker 退出且结果通道关闭后才释放其活动登记（缓冲结果仍可读取）。Pipeline 内不得同步调用所属 Engine.Close，应取消 context；消费者提前停止读取结果时也应取消或关闭 Engine。

主机并发槽按持有者与等待者共同引用计数，最后一个引用释放即移除；不能在仍有等待者时淘汰并创建第二套配额。Send/流共享 Engine 级槽，Run 使用独立调度器配额，彼此不合并。成功主机不保留零错误记录；失败计数与已跳过标记为单次 Run 所有，保留至成功重置或 Run 结束，跳过标记不会被晚到的成功响应撤销。Run 结束后释放全部历史，下一次 Run 不继承；为保持精确错误阈值，单次长 Run 的不同失败/跳过主机数量仍影响内存，不承诺全局固定内存预算。

## 配置与已有语义

| Config 字段 | 零值/默认行为 |
| --- | --- |
| Threads | 50 |
| MaxConcurrentPerHost | 10 |
| RatePerSecond | 150，非正数会补默认值 |
| RatePerMinute | 0 不限，与秒级限流同时生效 |
| Delay | 0；请求开始前额外延迟 |
| Retries | 0 补 2，负数禁用；仅 GET/HEAD/OPTIONS 网络错误，HTTP 错误状态不重试；被 RetryPolicy 覆盖 |
| RetryPolicy | nil 使用上述兼容策略；非 nil 显式启用策略，零对象禁用重试 |
| MaxHostErrors | 30，Run 的主机错误阈值 |
| Timeout | 10 秒，单次尝试（保留既有优先级） |
| PhaseTimeouts | 零值关闭额外阶段/跨尝试预算；负值令 New 报错，见下文 |
| MaxBodySize | 2 MiB，缓冲响应上限 |
| CookieJar | false；开启且未注入 Session 时创建私有有界会话 |
| Session | nil；非 nil 显式启用并共享调用方内存会话（不要求 CookieJar=true） |
| ConnectionPool | nil；保留每次尝试新建客户端。非 nil 显式启用有界复用，见下文 |

根包 Request.VerifyTLS 默认 false；调用方应显式选择。自定义根和客户端证书不改变该开关。
Send 与 Run 现在统一采用方法/正文重放检查，缺省仅 GET/HEAD/OPTIONS；Raw 和 one-shot Upload 不自动重试。显式 RetryPolicy 可以选择其他方法和状态，但不能越过正文可重放限制。完整退避/观察契约见 [重试说明](RETRIES.md)。
Send、Run、SendStream 的单次尝试总超时仍为：正值 Request.Timeout 优先，否则使用 Config.Timeout（配置缺省 10 秒）；更早的调用方 context deadline 始终有效。超时覆盖单次尝试的建连至正文读取，不包含 Engine 等待并发槽/限流的时间。TCP 拨号缺省保留 10 秒后备上限；显式正值 PhaseTimeouts.Connect 由该次连接阶段预算接管，不再被固定 10 秒截断。直接 Transport.RoundTrip 没有 Engine 配置，Request.Timeout 缺省为 10 秒；直接调用不创建跨尝试 Total 预算，应由调用方提供 context deadline。不修改调用方 Request；调用期间及未关闭的流存续期间，请求、Profile/TLS 对象应保持不可变。
SendStream 不重试且不截断正文；有效总超时也覆盖返回响应头之后的正文读取。

### 上传、会话、认证与请求规范化

- `Request.Upload` 与 bytes Body 二选一；使用 NewUpload/NewReplayableUpload 创建源，使用 NewMultipartUpload 创建懒读取 multipart。长度/关闭/取消/重放、CaptureRequestBody（默认0、最大1 MiB）及 Response.UploadEvidence 见 [上传说明](REQUEST-BODIES.md)。离线转换不打开或复制 reader 内容。
- `Config.Session` 支持显式注入共享 Session；默认256主机、每主机64cookie、空闲30分钟，支持 Clear/ClearHost 和 RFC path/secure/expiry。legacy CookieJar=true 也使用有界存储；不持久化。详见 [会话说明](SESSIONS.md)。
- `Request.Auth` 显式选择 Basic/Digest 或原生 ChallengeAuthenticator 扩展。挑战轮数有限，保留正文需可重放，凭据只限当前 origin；错误凭据的最终401仍是正常 HTTP 响应。详见 [认证说明](AUTHENTICATION.md)。
- 普通请求拒绝无效头字段/控制字节/大小写重复字段名/歧义 framing，Content-Length 必须匹配已知源，Transfer-Encoding 由 transport 控制。Host 不改变 URL、dial、SNI 或 origin。RequestHeaders 的 Authorization/Proxy-Authorization/Cookie 脱敏；显式上传证据仍可能包含秘密。
- Raw 原样发送调用方字节，不应用上传、CookieJar、认证、重试或自动重定向；仍保留地址/代理/阶段超时等安全边界。不提供 reader/path JSON 反序列化，也不扩大 curl CLI 支持范围。
- `nethttp.RequestInput` 提供 `auth`、`retry`、`capture_request_body` 结构化字段，native-only Upload/StreamingMultipart 使用 json:"-"；既有 BasicAuth 保持兼容，但不能同时提供 Auth。毫秒退避参数、冲突及安全校验见上述所属说明。

### TLS 版本、身份与公钥 pinning

`Request.TLSConfig *TLSOptions` 在既有内存 Roots/Certificates 上增加以下可选控制；不引入文件读取。nil 或这些新字段全为零值时保留既有握手路径和默认浏览器 Profile。`Validate()` 校验语法与范围，`Clone()` 复制控制字段与 pin 列表；信任池、证书和私钥仍是调用方持有的不可变引用，使用期间不得修改。

```go
req := &netloom.Request{
    URL: "https://service.example/api",
    VerifyTLS: true,
    TLSConfig: &netloom.TLSOptions{
        MinVersion: netloom.TLSVersion12,
        MaxVersion: netloom.TLSVersion13,
        ServerName: "service.example",
        // 用调用方可信来源获取的实际 leaf SPKI SHA256 替换此语法示例。
        PinnedPublicKeys: []string{"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
    },
}
```

- MinVersion/MaxVersion 类型为 TLSVersion，接受 `""`、`"1.0"`、`"1.1"`、`"1.2"`、`"1.3"`，对应 TLSVersion10..13；空值继承默认 Profile 边界，min 不得大于 max。控制只收窄 Engine 冻结默认 Profile 实际广告的版本，不自动补充被 Profile 移除的旧版本；没有交集时在拨号前报 ErrTLSProfileConflict。显式 Request.Profile（即使恰好等于默认值）与非零版本范围同时配置也报该错。版本范围会改变 ClientHello，不再承诺原浏览器指纹等价；TLS1.0/1.1 字符串有效不代表当前默认 Profile 能协商它们。
- ServerName 使用 ASCII/punycode DNS 名或无方括号、无 zone 的 IP，并规范化大小写、根点和 IP。它同时控制实际 SNI 与证书验证名，不改变 URL、HTTP Host、拨号目标、Cookie/origin 或重定向。IP 用于证书 IP SAN 验证，不作为 wire SNI 发送。未指定时验证身份仍是逻辑 URL 主机，显式 Profile 内嵌 SNI 不能在启用这些控制时偷偷替换该身份。SNI/pins 可与显式 Profile 共用；显式 DNS ServerName 配合无 SNI extension 的 Profile 报 ErrTLSProfileConflict，在 HTTP 应用数据前失败（可能已经完成 TCP/CONNECT）。
- PinnedPublicKeys 是最多 16 个不重复的 `sha256//BASE64`，严格使用带 padding 的规范标准 base64、解码为 32 字节。匹配实际 peer **叶证书**的 DER SubjectPublicKeyInfo SHA256，多个 pin 任一命中即可；不接受文件、公钥 PEM、证书全文 hash、CA/intermediate pin 或其他算法。叶公钥不匹配可用 `errors.Is(err, ErrTLSPinMismatch)` 判断，不触发透明重试；比较与存储均局限当前连接，不使用依赖的进程级 pin 表。
- pinning 不改变 VerifyTLS：false 时仍要求 pin 命中但不验证 CA/名称；true 时正常 CA/名称验证和 pin 都必须通过。正确 pin 不豁免过期、未知 CA 或错误名称。信任根与 mTLS 仍可同时使用。
- 非零新控制只支持 HTTPS 直连及 `http://` CONNECT 代理；HTTP URL、HTTPS/SOCKS 等其他代理返回 ErrTLSOptionsUnsupported，不静默忽略。Raw 保持不支持任何代理；Raw 的 TLS 控制作用于 URL 对应实际握手，不重写原始请求字节。Network 非零策略仍只支持直连，不因 TLS 支持 CONNECT 而放宽。
- 普通 H1/H2、严格 H2、缓冲/流式与 Raw 均在实际请求 socket 上实施，不增加探测连接、不替换为标准库 TLS。普通缓冲/流式启用这些控制使用有界一次性客户端租约，不参与缓存；连接直到正文关闭才释放，流始终须 Close。Raw 延续独立 socket 生命周期，不使用客户端池。阶段超时、取消和 Total 继续有效；严格 H2 不因控制配置而降级。
- Do 跨 origin 重定向仍清除整个 TLSConfig（含 trust/mTLS/版本/ServerName/pins），避免泄漏上一 origin 的 TLS 身份；同 origin 保留独立快照。跨 origin 新请求需要新 pin 时由调用方显式逐跳配置，不能假设原 pin 会跟随。

`nethttp.RequestInput.TLS` / `tls` JSON 对象接受 `min_version`、`max_version`、`server_name`、`pinned_public_keys`，不接受凭据路径或自动读取凭据。BuildRequest 校验并复制 pin 列表；缺失/null 为 nil，空对象为非 nil 空配置，仍走一次性租约。结构化转换只作字段校验，Profile/URL/代理兼容性由运行时检查；不新增 curl CLI 选项解析承诺。

### 直连网络映射与地址族

`Request.Network *NetworkOptions` 是每请求策略，没有 Engine 缺省覆盖。nil、空对象和仅 `AddressFamily: "auto"` 保留原先拨号行为。`NetworkOptions.Validate()` 无 IO 地校验整组规则，`Clone()` 深拷贝规则及 IP 列表；Send/Run、SendStream 与重定向会保存独立网络策略快照，调用期间仍不得并发修改输入。

```go
req := &netloom.Request{
    URL: "https://service.example/api",
    VerifyTLS: true,
    Network: &netloom.NetworkOptions{
        AddressFamily: netloom.AddressFamilyIPv4,
        ConnectTo: []netloom.ConnectToRule{{
            Host: "service.example", Port: 443,
            ConnectHost: "backend.example", ConnectPort: 8443,
        }},
        Resolve: []netloom.ResolveRule{{
            Host: "backend.example", Port: 8443,
            Addresses: []string{"192.0.2.10", "192.0.2.11"},
        }},
    },
}
```

示例使用文档专用地址，调用方必须提供实际允许的目标。其语义是：逻辑地址保持 `service.example:443`，只把 socket 送到 IP 列表的 8443 端口；HTTP Host、TLS SNI、证书验证名、Cookie/origin 与重定向 URL 均不替换。VerifyTLS 仍须显式启用，不因映射而自动开启。Raw 同样只改变 URL 对应 socket，原始 Host 等字节不重写；SendStream 仍不支持 Raw。

- Resolve、ConnectTo 均按主机和端口精确匹配；规则端口与替换端口必须为 1..65535，没有通配符、CIDR、零端口继承或递归替换。先应用一次 ConnectTo，再以有效目标匹配 Resolve；Resolve 不匹配时解析有效目标，而非原始逻辑主机。HTTP/HTTPS 的原始缺省端口分别为 80/443，每次重连、每跳重定向重新匹配。
- 主机使用 ASCII/punycode 名或无方括号、无 zone 的 IP。名字标签接受 ASCII 字母、数字、连字符及下划线；匹配时忽略大小写与一个末尾根点，IP 规范化并将 IPv4-mapped IPv6 视作 IPv4。启用非零策略时逻辑 URL 主机同样要求 ASCII/punycode，避免与后端 IDNA 转换不一致；不新增 Unicode 自动转换。重复的规范键、重复 IP、无效的未匹配规则也报错。每种规则最多 64 条，每条 Resolve 需 1..16 个 IP literal，不接受地址字段中的 DNS 名。
- 地址族为 `""`/`"auto"`、`"ipv4"` 或 `"ipv6"`（对应 AddressFamily 常量）。它筛选最终 IP，包括本地 DNS 答案和 Resolve 候选；与 tcp4/tcp6 冲突、筛选后无候选时失败，不回退其他族。候选顺序依次尝试，共享当前 context/Connect 预算，不实现 Happy Eyeballs；匹配 Resolve 的候选失败后不再偷偷回退 DNS。供给的 IP 不计作 DNS 查询时长。
- `LocalAddress` 绑定实际 TCP socket 的源 IP，仅接受不含 zone 的明确单播 IP literal；IPv4-mapped 规范化为 IPv4，源地址隐式约束目标地址族，显式族冲突报 `ErrNetworkBindingInvalid`。不接受主机名、端口、未指定/组播/有限广播地址，不指定源端口。
- `Interface` 仅 Linux，通过实际 socket 的 `SO_BINDTODEVICE` 绑定设备；名称为 1–15 字节可打印 ASCII，排除空白、`/`、`:`、`.`、`..`。非 Linux 在 Validate/BuildRequest 即返回 `ErrNetworkBindingUnsupported`。实际设备/权限/源地址绑定失败返回 `ErrNetworkBinding` 并保留系统原因，不自动重试或退回未绑定连接。只绑定目标 TCP，不约束 DNS resolver 出口；接口存在性和可达性不属于无 IO 验证。完整示例、权限和限制见 [本地源 IP 与 Linux 网卡绑定](NETWORK-BINDING.md)。
- 非零策略只支持直连；与任意 Proxy 同时使用均返回可由 `errors.Is` 判断的 `ErrNetworkProxyUnsupported`，即便规则未匹配，也不静默忽略。零策略保留既有代理语义；不宣称支持代理端解析控制、代理出口地址族或公共自定义 DNS server 配置。
- 生产地址保护继续拒绝 loopback、unspecified、link-local，不将 RFC1918 一概拒绝。逻辑 URL 的受阻 IP（含规范等价拼写）不能借映射绕过；每个最终 literal 在实际拨号前检查，DNS 解析后只拨所选 literal，避免二次解析 rebinding。原始逻辑 DNS 名不会为了校验而额外解析。非零策略关闭 CNAME 补充查询，故 CNAME 留空，不额外泄漏逻辑 DNS 或消耗预算。跳过的受阻候选不把其他允许地址的临时连接失败误判为永久阻止。
- 连接池按完整规范策略隔离，包含规范化源 IP 和设备名；等价 IPv4/mapped 源可共享，不同源或设备不能串池。绑定只在新建 socket 时执行，复用不重新检查设备或路由；网络变化后需 FreshConnection 或新 Engine，不自动迁移。规则顺序不影响身份，但 Resolve IP 的优先顺序影响；nil/空/auto 等价。即便某条规则当前未匹配，策略不同也不串用连接。重定向仍按逻辑 origin 清理跨域凭据；显式映射可能把同一逻辑 origin 的凭据送往另一实际端点，这是调用方授权范围，尤其须注意关闭证书验证时的风险。映射不授予地址保护豁免。

`nethttp.RequestInput.Network` 接受同名 `network` JSON 对象：`local_address`、`interface`、`address_family`、`resolve`（host/port/addresses）、`connect_to`（host/port/connect_host/connect_port）。BuildRequest 校验并深拷贝；不承诺 curl 文本的 `--resolve`/`--connect-to` 解析。

### 阶段超时与总体预算

`Config.PhaseTimeouts PhaseTimeouts` 是 Engine 缺省策略；`Request.PhaseTimeouts *PhaseTimeouts` 为整组覆盖：nil 继承 Engine，非 nil 零值关闭整组额外预算，不按字段合并。各字段是 Go `time.Duration`，零值不启动相应计时器，负值报错；既有单次 Timeout 与调用方更早 deadline 不被延长。阶段策略在实际当前租约上生效，不把不同阶段期限固化进可复用客户端。

| 字段 | 实际计时边界 |
| --- | --- |
| Connect | 本次拨号开始至 DNS、TCP 及 HTTP 代理 CONNECT 完成；复用已有连接不重复消耗 |
| TLSHandshake | TCP/CONNECT 完成至 HTTP 连接就绪，包含实际 uTLS 握手以及 H2 preface/初始化；不是精确的纯 TLS 握手时长 |
| ResponseHeader | 成功写完请求后，至完整最终响应头返回；收到首字节、103 等中间头或部分最终头不会结束预算 |
| BodyIdle | 每一次阻塞 Body.Read 的预算；新一次读取重新计时，流式调用方处理数据/暂停消费时不计时；不是全正文时长或字节限速 |
| Total | Send/Run 在并发槽、限流/Delay 排队完成后开始，横跨所有尝试及其正文；SendStream 同样在准入后开始且覆盖流式读取 |

客户端池租约等待包含在单次 Timeout/Total 中，尚未建连时不计算 Connect/TLS/Header；请求写入阶段由单次 Timeout/Total/context 约束，没有独立上传超时字段。阶段 timer 结束会取消实际当前 socket，不在后台留下假超时握手；BodyIdle 失败保留已收到的 headers/部分正文，流式状态在 `Status().Error` 可见。流仍必须 Close。

`Do` 对整个重定向链只启动一次 Total（包括每跳内部重试）。其预算在 Do 校验入参后、首跳前开始，因此包含 Do 内部的 Send 排队和跳转校验等待。显式请求策略优先；nil 时仅当 sender 是直接 `*Engine` 才能读取该 Engine 缺省策略，包装器/任意 Sender 必须显式传入请求策略或 context deadline。自定义 Sender 必须遵守 context 才能被中断。需要包含 Send/Run 最初排队时间的严格端到端预算仍应使用调用方 context deadline。

阶段预算当前只支持直连及 `http://` 代理；包含 Total 在内的任意非零策略用于其他代理 scheme 会显式报错，避免声称已经解决第三方代理拨号器的实时取消限制。整组零值时保留原先非严格路径的其他代理行为。Raw 同样支持阶段预算并保留原始 HTTP 字节、部分响应和既有 best-effort 解析，但不应用自动跳转；直接 RoundTrip 不启动 Total。

网络/正文失败可用 `errors.As(err, &phaseError)` 取得 `*PhaseError`。`Phase` 为 `pool`、`connect`、`tls`、`request`、`response_header`、`body` 或 `total`，标识观察到失败的操作，不推断未观测的根因。阶段/Total 期限满足 `errors.Is(err, context.DeadlineExceeded)` 和 `net.Error.Timeout()`；调用方取消仍满足 `errors.Is(err, context.Canceled)`，in-flight 的自定义取消 cause 也保留。底层地址阻止、TLS 验证等错误继续可用 errors.Is/As 判断；参数/排队错误不承诺一定有 PhaseError。错误包装不附加 URL 或凭据，但不对底层错误文本做脱敏；不得直接将含秘密的错误持久化或展示。

例如，在保留既有单次 Timeout 的同时为多次尝试提供预算：

```go
engine, err := netloom.New(netloom.Config{
    Timeout: 10 * time.Second,
    PhaseTimeouts: netloom.PhaseTimeouts{
        Connect: 2 * time.Second, TLSHandshake: 3 * time.Second,
        ResponseHeader: 4 * time.Second, BodyIdle: 2 * time.Second,
        Total: 15 * time.Second,
    },
})
```

`nethttp.RequestInput.PhaseTimeouts` 是可选 `*PhaseTimeoutsInput`，JSON 字段为 `phase_timeouts`，内部整数毫秒字段为 `connect_ms`、`tls_handshake_ms`、`response_header_ms`、`body_idle_ms`、`total_ms`。省略/null 继承，`{}` 关闭整组；负数和转换为 Duration 时溢出均报错。此输入适配不等价于支持对应 curl CLI 选项。

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
- CookieJar 保留 host（含显式端口）会话隔离；客户端池 LRU 驱逐不会清空 Cookie。Session 存储与客户端池独立，由 SessionConfig 的 host/cookie/idle 限制控制；不能将 MaxClients 当作全部会话内存上限。Raw 不使用此池。
- 直连及 HTTP CONNECT 的底层连接按当前独占租约绑定 context，覆盖第三方 H2 后台重连的 TCP/TLS/初始化；请求结束成功归还前解除旧取消回调，避免一次请求取消误关后续租约。过期 H2 连接重拨不会获得脱离请求预算的后台握手。
- 复用响应仍从实际连接读取 TLS/IP，不复制上次的 DNS/Connect/TLS timings；复用时没有发生的阶段保持 nil。代理路径不将代理 TCP peer 冒充目标出口 IP。

### 失败与部分响应

Send/Transport.RoundTrip 可同时返回非 nil Response 和非 nil error。状态码、headers 和已读正文仍是有效的部分证据，不能因 error 丢弃，也不能将它视为完整成功。BodyTruncated 仅表示大小上限导致的主动截断；读取失败由 error/Response.Error 表示。
重试失败保留最近一次非 nil 响应，返回的 error 是最终失败原因，两者可能来自不同尝试；逐次观察可显式配置 RetryPolicy.Observer，不自动无限保留尝试历史。Run 失败时同样保留证据，并将最终错误写入 Response.Error，不执行成功分析 Pipeline。重定向 Do 也会保留发送方返回的部分响应。

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

非空代理配置在准入前进行本地语法验证，错误通过 `errors.Is(err, netloom.ErrInvalidProxy)` 判断，不重试、不隐式直连，也不累计目标主机错误；Run 按 Task.Mutators 的最终请求验证。只有空字符串表示直连，空白字符串不会被转换为直连。根包支持 HTTP/HTTPS、SOCKS4/SOCKS4A/SOCKS5/SOCKS5H，SOCKS 必须显式给端口；拒绝缺少 scheme/host、无效端口、非根路径、query 和 fragment。配置错误文本不回显代理 URL 或用户名密码；这不是对调用方日志和请求快照的自动脱敏。Raw 与代理仍不兼容，其他协议/TLS/网络选项的组合限制保持不变。

## 所有权、背压与关闭

Send 将正文读入内存并关闭底层 Body；BodyTruncated 标明主动截断。
SendStream 的调用方必须关闭 Body，即使已读到 EOF；Close 幂等并释放并发槽和连接。取消请求上下文或关闭 Engine 也会关闭活动流。
结果快照在交给分析器后由调用方保证不再修改；netloomdata 转换复制正文、Header 和所需 TLS 字段。
不要在并发发送期间修改 Request、TLSOptions、Config 或规则输入。

一个 Engine 同时只接受一个 Run，重复调用返回 ErrEngineBusy。
Run 返回有界结果通道；消费者须持续读取或取消上下文。Submit 队列满、未运行或已关闭时返回 false；Schedule 丢弃该布尔值。
派生任务使用 Context.TryEmit 处理背压，或 Emit 将拒绝转为 ErrQueueFull；工作线程不会阻塞等待自己的队列。
Context.Next 支持嵌套的前后处理；当前实现也会继续执行未显式 Next 的后续处理器。要终止必须 Abort。

Task.Mutators 是发送前请求变换阶段：按顺序在请求副本上执行一次，先于 host 配额选择、请求校验和重试；重试复用变换结果，不重复调用 Mutator。副本复制 Header、HeaderOrder、Body、Raw 及 Network/TLS/Auth/Retry/PhaseTimeouts 配置；Upload 仍是共享且管理一次性消费的正文源，Profile 及自定义扩展仍须遵守不可变约定。Mutator 不得保留请求异步修改；跨任务复用的 Mutator 须并发安全。变换失败时不发送、不执行响应 Pipeline，结果 Response.Error 保留错误链。

Task.Pipeline 只处理已取得的响应，不能改变当前线上请求。旧 AsMutator 仅保留给尚无 Response 的独立 Context；用于 Run 的响应 Pipeline 或任何已有 Response 的 Context 时返回 ErrMutatorAfterSend，不再事后改写请求。请将 `Pipeline: []Handler{AsMutator(m), analyze}` 迁移为 `Mutators: []Mutator{m}, Pipeline: []Handler{analyze}`。单独使用 Send/Do 的调用方应在调用前完成请求变换；probe 在构造请求时设置代理、TLS profile 和请求头，响应 Pipeline 仅保留提取器。

Run 和独立 Send 的限流器分别计数；并非跨所有入口的统一速率配额。

Engine.Close 幂等，阻止新工作，取消已有请求及队列、关闭活动流，唤醒租约等待者，并在工作退出后关闭池内空闲连接。
请勿在本 Engine 的 Pipeline 处理器内调用 Close；应取消上下文，由拥有 Engine 的外层关闭。
自定义处理器若忽略上下文并永久阻塞，Close 同样会等待它退出。

## API 查询包

httpclient 是独立的标准库 HTTP 会话，不能套用根包的零值配置、TLS 指纹或拨号防护。`NewSession` 保留无 error 返回签名，通过 `Session.Err()` 检查不可变构造错误；无效代理使 Get/Post/Do 在限流和正文重放前返回 `httpclient.ErrInvalidProxy`，不再忽略代理后直连，不支持的 scheme 还可用 `ErrUnsupportedProxy` 判断。其代理支持 HTTP/HTTPS、SOCKS5/SOCKS5H，不支持根包的 SOCKS4。mapping 与 enterprise 使用调用方提供的凭据读取接口，不内置数据库或密钥服务。重试可能产生重复付费请求，须由调用方明确选择。

`httpclient.Options.RetryMethods` 为 nil 时仅 GET/HEAD/OPTIONS 可自动重试，非 nil 空切片禁用全部方法的重试；允许列表在构造时复制，按大写方法 token 精确匹配；非法或非大写项被忽略，全部无效也不会回退默认列表。POST/PATCH 等须由调用方明确加入列表，且正文必须可重放（Post 的字节正文或 Do 的 GetBody）；不可重放的流只发送初次请求。RetryMax/DisableRetries 再限制次数，不自动把非安全方法加入列表。此策略控制 SDK 的重试循环，不承诺 exactly-once；即使是 GET，也可能重复计费，付费查询应明确使用 DisableRetries。禁用本包重试不会禁止 Go 底层 Transport 在复用连接故障等条件下的自动重发，仍需数据源的幂等/计费协议，不能把它当作绝不重复的保证。

mapping/enterprise 区分“缺少凭据”与“读取失败”：nil 读取器或无错误的空/空白必需凭据使用各包的未配置 sentinel，SecretReader.Get 的错误则包装并保留 errors.Is 错误链，返回了字节也不能忽略伴随错误。读取失败不会发起 HTTP 请求。FOFA 的可选邮箱若读取失败同样终止；每次 Search 在分页前读取一次 key/email，下次 Search 重新读取。爱企查每次公开查询重新读取并修剪 Cookie；本包仍不提供凭据存储或错误内容的通用脱敏。

包级配置、响应体所有权、限流与限制分别见 [httpclient](../httpclient/README.md)、[mapping](../mapping/README.md) 和 [enterprise](../enterprise/README.md)。

## 扩展契约

离线 fingerprint、infoextract、passive 使用 httpdata 快照，不依赖网络运行时；不需要创建 Engine。`ac` 是独立公共字节串匹配包，导入路径为 `github.com/emhha/netloom/ac`：

```go
// package ac
func New([]string) *Matcher
func (*Matcher) Search([]byte) map[string]struct{}
func (*Matcher) Match([]byte, func(index int))
```

`ac` 薄适配固定版本的 Cloudflare ahocorasick，共享扫描统一使用上游 `MatchThreadSafe`。`Search` 返回独立的命中关键词集合；`Match` 每次为每个命中唯一词最多回调一次，提供该词在输入中的第一个原始索引，不承诺顺序或出现次数，适合映射到候选规则。空关键词忽略，重复关键词去重。详细字节匹配及回调契约见 [ac 说明](../ac/README.md)。共享的是匹配引擎，不是 Registry 级的统一预筛选：Registry 不强制所有插件使用 AC，各插件自行选择是否复用。
指纹推荐通过 Config.RulesDir 显式指定规则目录并加载 sources.json，当前禁用 webfinger、启用 EHole/FingerprintHub/Wappalyzer。配置模式对启用文件的缺失、空文件、无效原生格式返回错误；不与逐文件字段混用。

保留 WebfingerYAML、CustomRulesDir、WappalyzerJSONPath，新增 EHoleJSONPath、FingerprintHubJSONPath 作为独立显式输入，不读取 sources.json。旧 YAML/Wappalyzer 输入保持原有缺失文件降级语义；两个新原生 JSON 输入返回加载错误。零值配置不读文件。规则来源与格式细节见 [规则说明](../fingerprint/rules/README.md)。

MatchExchange(ctx, *httpdata.Request, *httpdata.Response) 额外校验 FingerprintHub 原生探针方法、路径和请求头，并支持已抓取 POST 响应。Match(ctx, response) 保留兼容；没有请求上下文时只评估普通 GET、通用首页探针。Response.URL 可约束路径，Response.FaviconMD5 和原 FaviconHash 作为调用方已捕获图标的证据。内置 passive 指纹插件已传入请求上下文，缓存键覆盖图标 MD5 与正文截断状态。

EHole/FingerprintHub 的 AC、图标及正则字面量索引在 New 时构建，Engine 可并发复用。正文转换和请求约束缓存均限于单次调用，不共享可变匹配状态。优化不改变条件、结果顺序、版本或置信度；缺少可证明必要的字面量时会退回完整正则检查。详见 [性能记录](PERFORMANCE.md)。

webfinger.go 提供独立 WebfingerMatcher、LoadWebfingerYAML 与 Len（包含仅图标规则的去重技术数），和其他来源保持同类入口结构。Engine 不再持有 webfinger 的 AST/AC/图标内部状态；底层 lexer/parser/ast/compiler 继续独立组织。默认来源开关保持不变。
infoextract 复用公共 `ac` 筛选触发词，仍可通过 `infoextract.New` 独立使用；`Extract`、`ExtractWithContentType`、`AddRule` 与既有 `plugins.Information` 插件入口保留。默认仅加载高敏感凭据类规则，可 AddRule 显式扩展；邮箱、内网 IP、linkfinder 等不属于当前内置规则。有触发词的规则在任一触发词命中后执行正则，无触发词规则保留 fallback；正文/响应头路由与结果语义不变。独立调用和扩展规则的约束见 [infoextract 说明](../infoextract/README.md)。passive.New 显式选择插件与内存缓存容量。

`InfoExtractor.Snapshot()` 捕获不可变规则、AC 索引及 `Identity()`；身份仅在进程内唯一，不是持久化版本号。成功 `AddRule` 发布新身份，失败不改变当前代次。直接提取的一次调用也固定正文和响应头使用同一快照。`plugins.Information` 每次分析绑定同一代次的正文/响应头缓存，规则更新后不命中旧代次结果；在途旧分析允许按原快照完成，但不污染新缓存。配置字段 `Extractor`、`CacheLimit` 不应在分析期间并发写入；提取器本身允许并发 `AddRule`。nil Extractor 返回错误；Information 元数据版本为 `"4"`。

`passive/plugins.Serialization` 实现 `passive.Plugin`，零值可用；通过 `passive.New([]passive.Plugin{&plugins.Serialization{}}, cacheLimit)` 显式注册，ID 为 `serialization`、Version 为 `"1"`，不自动启用。它纯离线扫描请求 URL/头/正文和响应头/正文，仅做一层 URL/form 与有界标准/URL-safe Base64 解码，不反序列化、不联网、不解压/解密或跨流关联。每输入固定总扫描 1 MiB、128 个观察面、64 个 findings；超限或输入 Response.BodyTruncated 时标记 Result.Truncated。

Serialization 的文本规则复用公共 `ac` 筛选候选，仅对候选执行相应正则；可证明等价的安全固定字面量规则直接命中，无法安全提取必要触发词的规则保留完整正则 fallback。大小写不敏感的 `rememberMe` 继续使用正则 fallback，避免以 ASCII 大小写预筛选漏掉 Go 正则支持的 Unicode 折叠匹配。二进制 magic 保持前缀检查，不改为任意位置的 AC 命中；URL/Base64 观察流程、上述 1 MiB/128/64 预算、finding 顺序与输出语义不变。

公开 `plugins.SerializationFinding` 包含 Format、Rule、Strength、Scope、Encoding、Evidence 字段；`Result.Data` 为 `{findings: [{format, rule, strength, scope, encoding, evidence}], passive_only: true}` JSON。Serialization.CacheKey 返回空字符串，禁用结果缓存。strength 的 strong/medium/weak 仅表示特征强度，不代表漏洞；响应内容特征降级，错误串仅作响应线索。Artifacts 的 Type 为 `serialization_hint`，Rule/Scope 对应规则和观察位置，Value 仅含格式名及强度；evidence 为有界特征标签，不回显原始敏感值。完整调用示例、解码边界和误判说明见 [内置被动插件](../passive/plugins/README.md)。

probe.Run 返回结果通道，dirscan.Run 返回结果切片。调用方负责目标授权；无数据库或任务服务。

`dirscan.Config.Threads` 为每目录的有界请求/重排窗口（默认 30），Engine 的全局与同主机并发上限与其一致，仍受默认 150 次逻辑请求/秒准入限流约束。worker 仅发送请求，单协调器按派发顺序聚合；目录和 wildcard 校准保持串行。Crawl 优先尚未派发的字典，不抢占在途任务；并发发现会影响后续派发顺序。取消或 MaxTime 到期停止派发并等待在途退出，保留已完成且通过过滤/去重的结果并返回 context 错误。连续错误达到阈值仅停止该目录，最多已有 Threads-1 个后续任务被接纳。字数/行数过滤使用正文实际计数。窗口不限制整个发现队列或结果总量；完整语义见 [目录扫描说明](../dirscan/README.md)。

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
