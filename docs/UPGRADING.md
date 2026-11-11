# 升级说明

## 当前开发版本

### 公开导入路径

统一使用 module `github.com/emhha/netloom`，根包标识符为 `netloom`，子包位于同一 module 下。使用早期裸路径 `netloom` 的代码应更新 module 依赖及导入路径，例如：

```go
import "github.com/emhha/netloom"
import "github.com/emhha/netloom/httpdata/netloomdata"
```

不提供旧 module 路径的兼容包。安装方式见 [安装与使用](MIGRATION.md)。

新增公共包 `github.com/emhha/netloom/ac`，提供 `ac.New([]string) *ac.Matcher`、`(*ac.Matcher).Search([]byte) map[string]struct{}` 与 `(*ac.Matcher).Match([]byte, func(index int))`。它薄适配固定版本 Cloudflare ahocorasick，统一使用线程安全扫描；空词忽略、重复词保留第一个原始下标。`Match` 每个命中唯一词每次最多回调一次，不保证顺序或 occurrence 次数，不是位置枚举接口。调用方可独立复用字节串匹配引擎，详见 [ac 说明](../ac/README.md)。`infoextract` 改为复用此包，原 `infoextract.New`、提取/注册规则接口及 `plugins.Information` 入口保留，无需改为通过 Registry 才能使用；见 [infoextract 说明](../infoextract/README.md)。

### 默认值与可见行为

- **API 会话默认不重试具副作用方法**：`httpclient.Options.RetryMethods` 为 nil 仅允许 GET/HEAD/OPTIONS，非 nil 空列表不重试任何方法；构造时复制，按大写方法精确匹配。旧默认会重试 POST/PATCH 的调用方须重新确认业务可重入性，再显式加入列表，并保证正文可重放。一次性流即便方法获准也只发送一次；DisableRetries/负 RetryMax 仍优先，RetryMax 为 0 仍表示默认最多三次重试。根包 RetryPolicy 的显式 opt-in 语义不变。付费 GET 仍建议禁重试，此变化不提供 exactly-once 保证。
- **凭据读取错误不再伪装成未配置**：mapping/enterprise 现在包装 SecretReader.Get 的非 nil 错误，可 errors.Is 判断底层取消、超时或存储故障；即使同时返回字节也不发送请求。只有 nil 读取器或无错误的空/空白必需值使用原有 ErrEngineNotConfigured/ErrNotConfigured。FOFA 的可选 fofa_email 读取故障同样失败，key/email 每次 Search 在分页前各读取一次；爱企查将纯空白 Cookie 视为未配置。此前统一捕获“未配置”的调用方应分别处理存储失败与配置缺失。

- **代理配置失败关闭**：`httpclient.NewSession` 不再忽略无效代理后直连，保留构造函数签名，新增 `Session.Err()`；请求方法返回可 `errors.Is` 判断的 `ErrInvalidProxy`，不支持 scheme 仍可判断 `ErrUnsupportedProxy`。根包同步新增 `ErrInvalidProxy`，在最终请求变换后、准入前验证，错误不计入目标失败；配置错误不再回显代理地址/凭据。空字符串仍是直连，空白/缺少 scheme 或 host/无效端口/非根路径/query/fragment 改为明确拒绝；SOCKS 需显式端口。curl 不支持代理，未知选项错误不再回显整个原始 token。依赖旧隐式直连的调用方必须显式清空代理，而不是忽略错误。

- 调度器现在先完成运行 context、worker 和种子 feeder 保活初始化，再对 `Submit` 发布；`Run` 与 `Close` 竞争时不再在关闭后发布新调度器，`Close` 等待 Run 的结果通道关闭。single-flight、非阻塞接纳及队满返回 false 的接口不变。主机并发槽在最后一个持有者/等待者离开时立即回收，成功主机删除零错误记录，Run 结束释放错误/跳过历史；错误阈值和 Run 内 sticky skip 不因回收而弱化。单次长 Run 的失败主机历史仍非固定容量，详见 [生命周期契约](API.md#调度与主机状态生命周期)。

- `Task` 新增 `Mutators []Mutator`，按顺序在请求副本上执行一次，先于 host 配额选择、校验及重试；失败通过结果 `Response.Error` 返回，且不发送、不执行响应 Pipeline。`Task.Pipeline` 保持响应后分析；请把其中的 `AsMutator(m)` 移到 `Mutators: []Mutator{m}`。`AsMutator` 标记弃用，只保留独立发送前 Context 的兼容入口；已有 Response 时返回可用 `errors.Is` 判断的 `ErrMutatorAfterSend`，不再改写已发送请求。单次 `Send`/`Do` 在调用前显式变换。`probe` 在构造请求时设置默认 User-Agent，自定义 User-Agent 仍覆盖它，响应分析不再运行请求 mutator。详见 [API 契约](API.md)。

- `infoextract` 新增 `Snapshot()`、`Snapshot.Identity()` 和快照的 `ExtractWithContentType`，规则、AC 索引和进程内唯一代次身份同时捕获；既有直接提取接口保留，并强化为一次调用的正文/响应头使用同一代规则。`plugins.Information` 按此身份替换内部缓存，成功 `AddRule` 后的新分析不再复用旧结果；在途旧分析仍可完成，但不会污染新代缓存。插件元数据版本从 `"3"` 升为 `"4"`；nil Extractor 改为返回明确错误。快照身份不是可持久化版本号；详见 [提取器说明](../infoextract/README.md) 和 [插件说明](../passive/plugins/README.md)。

- `dirscan.RecursionDepth` 现在相对固定 `BaseURL` 扫描根计算，逐层递归不再重置深度；Crawl 的 origin-absolute 路径不再重复拼接当前目录，且不跟随扫描根外链接。取消或 `MaxTime` 到期返回已完成结果及非 nil context 错误，调用方应同时处理部分结果与错误。扫描改为每目录有界并发：`Threads` 默认 30，设置 1 可串行；Engine 同主机上限同步设为 Threads，实际请求压力可能高于旧串行版本，应根据目标授权和承载显式设置。目录和 wildcard 校准仍串行，Crawl 仅优先未派发字典。响应按派发顺序聚合，窗口包含未聚合的乱序完成响应；取消后等待在途退出并保留成功完成的过滤后结果。连续错误现在同时正确计入 `Response.Error` 和 nil 响应；阈值后停止该目录，最多已有 Threads-1 个后续任务被接纳，成功尾部响应不会重启派发。字数/行数过滤改为使用正文实际计数，可能修正过去零值导致的错误筛选。详见 [目录扫描](../dirscan/README.md)。

- `infoextract.AddRule` 现在复制 `Triggers` 并以 copy-on-write 发布规则列表，修复并发同名替换对旧扫描快照的改写。返回后可复用原触发词切片；nil/零长度切片仍表示 fallback，只有空字符串的非空切片仍永不触发。不改变已有规则顺序、同名替换位置或独立提取入口。

- `Serialization` 的文本规则改用共享 AC 筛选候选，仅候选运行正则，安全固定字面量规则直接命中；无法安全触发的规则保留正则 fallback。大小写不敏感的 `rememberMe` 仍走正则，保留 Unicode 折叠匹配，不能用仅 ASCII 的大小写预筛选替代。magic 仍为前缀检查，URL/Base64 流程、1 MiB/128/64 固定预算与结果/证据语义不变。Registry 不新增强制 AC 策略，既有插件选择、注册和缓存接口不变；共享引擎由各插件自行选择使用。

- 新增公共插件 `passive/plugins.Serialization` 及结果类型 `plugins.SerializationFinding`；插件实现 `passive.Plugin`，零值可用；注册 ID 为 `serialization`、版本为 `"1"`。使用 `passive.New` 显式注册，不改变既有 Registry 的插件选择。它仅对已捕获请求 URL/头/正文和响应头/正文作离线特征扫描与一层有界解码，不反序列化、不联网；固定每输入总扫描 1 MiB、128 个观察面、64 个 findings，超限及 Response.BodyTruncated 传播至 Result.Truncated。Result.Data 新结构为 `{findings: [{format, rule, strength, scope, encoding, evidence}], passive_only: true}`，Artifacts 类型为 `serialization_hint`，仅含格式/强度及规则/位置元信息，不含原始敏感值。strong/medium/weak 是特征强度，不是漏洞结论；完整示例及误判边界见 [内置被动插件](../passive/plugins/README.md)。

- `NetworkOptions` 新增 `LocalAddress`（JSON `local_address`）与 `Interface`（`interface`），分别绑定实际 TCP 源 IP 和 Linux 网卡；空值不改变原行为，适用于普通/流式/Raw 直连，与任意代理组合仍明确拒绝。源地址约束目标族，完整规范策略进入池身份；绑定不影响逻辑 URL/Host/SNI，不绑定 DNS resolver、不修改系统配置。新增可用 errors.Is 判断的 `ErrNetworkBindingInvalid`、`ErrNetworkBindingUnsupported`、`ErrNetworkBinding`：前两类在验证阶段返回，后者保留内核原因且不自动重试/降级。Interface 在非 Linux 即验证失败；Linux 可能需要调用方授予 capability。已有连接不因设备变化自动重绑，重新建连须 FreshConnection 或新 Engine；详情见 [绑定指南](NETWORK-BINDING.md)。

- 阶段四新增 Request.Upload/NewUpload/NewReplayableUpload/NewMultipartUpload、CaptureRequestBody/UploadEvidence、Config.Session/NewSession、Config/Request.RetryPolicy 和 Request.Auth/ChallengeAuthenticator。详细生命周期分别见 [上传](REQUEST-BODIES.md)、[会话](SESSIONS.md)、[重试](RETRIES.md)、[认证](AUTHENTICATION.md)；不引入文件路径、隐式持久化或新的 CLI 选项全集。
- Send 与 Run 统一默认只重试 GET/HEAD/OPTIONS 网络错误，修复过去 Run 会重试有副作用方法的不一致；Raw 不再透明重试。显式 RetryPolicy 可放开方法/状态，不能放开不可重放正文。nil 继承，非 nil 零策略禁用，优先于 legacy Retries。
- legacy CookieJar=true 改用有界且遵守 Secure/Path/Domain/Expiry 的存储，默认256host/64cookie/30分钟 host idle；过去忽略 cookie path/secure 的行为不再兼容。显式 Config.Session 可跨 engine 共享，Clear 不撤回已发头且进行中的 Set-Cookie 可能再次填入。清理/淘汰后的缓存连接不持有旧 jar。
- 普通 native 请求现提前拒绝头部控制字节、无效字段名、大小写重复字段名、歧义 Host/Content-Length、手动 Transfer-Encoding，以及非 HTTP(S)/带 userinfo 的 URL。需要异常字节请求须显式 Raw，仍不得绕过地址/代理等安全限制。Response.RequestHeaders 的 Authorization/Proxy-Authorization/Cookie 改为 [REDACTED]；授权证据请调用方自行管理，而不是依赖诊断头保存凭据。
- 新增 ErrBodyNotReplayable/ErrUploadLength 及 ErrAuthOptions/ErrAuthChallenge/ErrAuthUnsupported，可经 errors.Is 判断；认证扩展自定义错误不回显凭据。最终401仍是正常响应；流式认证错误不返回未关闭的活跃响应流。

- 根包 `Request.VerifyTLS` 默认 false，验证证书须显式启用。`Config.Retries=0` 表示默认重试两次，负数禁用重试；路径调整不改变这些行为。
- Send/Run 的配置超时不再被底层隐式 10 秒总期限覆盖；SendStream 现在也遵守 Config.Timeout。优先级为正值 Request.Timeout > Config.Timeout > 默认 10 秒，调用方更早的 context deadline 仍有效。TCP 拨号缺省保留 10 秒后备上限，显式 PhaseTimeouts.Connect 正值可接管该上限。
- Send 在失败时可同时返回非 nil Response 与 error；Run 失败结果保留已收到的 headers/body。重试耗尽时响应是最近一次非 nil 证据，错误为最终失败原因，可能来自不同尝试；调用方必须检查 error，不将部分正文当作成功。
- 缓冲与流式请求只返回实际连接可获得的 TLS 元数据，不再隐式第二次握手；部分后端下 TLS 字段可能由过去的补探测值变为 nil。普通缓冲响应新增实际 trace timings，缺失阶段保留 nil。
- StreamResponse 新增 Status() 与 StreamStatus 完成快照；Response 保持响应头时元数据，不在后台更新。提前关闭且未观察 EOF 时 Status.Error 为 ErrStreamClosedEarly（取消和读取错误保留相应原因）；EOF 后仍须 Close。详情见 [API 与配置](API.md)。
- Request.HTTPVersion 新增 `2`（偏好 H2，允许降级）与 `2-only`（仅 HTTPS，发送 HTTP 前要求 ALPN h2）。空/auto 和 1.1 行为保持不变，不默认启用 H3/h2c。新增 ErrHTTP2Unavailable，具体协议与错误边界见 [API 与配置](API.md)。nethttp 结构化输入接受这些值；不承诺 curl 命令行选项全集。
- 普通/流式的 `http://` 代理 CONNECT 现在在取消时关闭 socket，响应头上限 64 KiB；代理 URL 的非根路径、query 和 fragment 不再被忽略而是报错。严格 H2 当前仅支持直连及 `http://` CONNECT，其他代理 scheme 明确拒绝；非严格请求的既有 HTTPS/SOCKS 代理支持不变，但其第三方拨号器仍有实时取消限制。
- 新增 Config.PhaseTimeouts 和 Request.PhaseTimeouts 整组覆盖（nil 继承、指针零值关闭），支持连接、TLS/HTTP setup、最终响应头、阻塞正文 Read idle 与跨重试/Do 重定向 Total。零值不启用额外 timer，单次 Timeout 语义不变。TLS 预算包含 H2 初始化；BodyIdle 不计流式消费暂停。Send/Run/Stream 的 Total 从准入后开始，Do 的外层 Total 包含内部 Send 等待；完整边界见 [API 与配置](API.md)。
- 网络失败新增 *PhaseError 包装；依赖字符串匹配或直接 error 类型断言的代码应改用 errors.Is/As。调用方取消、deadline、底层 TLS/地址阻止错误保留判断链；错误文本并非脱敏层。非零阶段策略（即使仅配置 Total）用于 HTTPS/SOCKS 等非 HTTP 代理现在会报错，整组零值时既有支持与取消限制保持不变。
- nethttp.RequestInput 新增 phase_timeouts 对象，内部 connect_ms/tls_handshake_ms/response_header_ms/body_idle_ms/total_ms 使用整数毫秒，负数或溢出报错；省略继承，空对象关闭整组。Raw 解析跳过 100/103 等中间响应、继续读取最终头（101 保持切换响应），阶段超时不再变成 best-effort 成功。
- 新增每请求 Request.Network、NetworkOptions/ResolveRule/ConnectToRule 与 AddressFamily 常量：只改变实际直连目标，保持逻辑 URL/Host/SNI/证书身份。nil、空对象和仅 auto 保留旧行为；规则规范化、精确 host+port 匹配并有界校验，先 ConnectTo 再 Resolve。非零策略与任意 Proxy 共用返回 ErrNetworkProxyUnsupported，逻辑 Unicode 主机须显式使用 punycode，不隐式 IDNA 转换；非零策略不再查询补充 CNAME。池按完整规范策略隔离，IPv4-mapped/根点拼写不能绕过受阻地址保护；IP 候选顺序影响复用身份。nethttp.RequestInput 新增 network 对象并深拷贝；详情及凭据路由风险见 [API 与配置](API.md)。不新增 Engine 网络缺省、自定义 DNS server 或代理映射；TLS 参数控制见下一条。
- TLSOptions 新增 MinVersion/MaxVersion（TLSVersion10..13）、ServerName 与 PinnedPublicKeys，nil/新字段全零保留既有路径。非零控制使用实际请求 socket 的独立 uTLS 握手及有界一次性租约，支持 HTTPS 直连/HTTP CONNECT，Raw 仍拒绝所有代理；其他 URL/代理报 ErrTLSOptionsUnsupported。版本范围仅收窄冻结默认 Profile 的广告版本，与显式 Request.Profile 共用或无交集报 ErrTLSProfileConflict；改变范围不承诺浏览器指纹等价。显式名称同时改变 SNI/验证名，不改 URL/Host/origin；IP 不发 SNI。启用控制时，Profile 内嵌 SNI 不再能替换逻辑 URL 的缺省验证身份；显式 DNS 名但 Profile 无 SNI extension 明确冲突。pin 为至多 16 个规范 sha256//BASE64、叶 SPKI SHA256 任一匹配，VerifyTLS 语义不变，错误新增 ErrTLSPinMismatch。跨 origin Do 清除整个 TLSConfig。nethttp 新增 tls 对象，字段校验/复制与运行时兼容性边界见 [API 与配置](API.md)，不承诺 curl CLI 新选项。
- nethttp.BuildRequest 的空 TLSProfile 现在保留隐式默认，由 Engine 的冻结快照解析，允许默认连接池生效；非空有效 profile 名仍是显式选择并旁路缓存。不要通过运行期间修改全局默认 Profile 来切换既有 Engine 的 TLS 身份；需新建 Engine。
- Config.ConnectionPool 非 nil 时显式启用有界、按 origin/代理/TLS 验证/协议隔离的顺序连接复用；nil 保留旧默认。MaxClients 缺省 64、IdleTimeout 缺省 30 秒，负值令 New 返回错误。显式 Profile、TLSConfig 和严格 H2 仍走受限的一次性租约。新增 Request.FreshConnection，可按次禁用复用；完整读完的流仍须 Close 才释放池租约。Cookie 会话存储不受客户端池上限控制。
- MITM 默认 CA CommonName 为 `netloom MITM CA`，代理认证 Realm 为 `netloom`。自定义名称通过 `AuthorityOptions.CommonName` 和代理选项配置；加载已有 PEM 不会修改证书名称。
- 企业信息包凭据缺失返回 `ErrNotConfigured`，错误说明指向凭据读取接口及 `aiqicha_cookie` 键。判断错误应使用 `errors.Is`，不要依赖提示文本。
- `infoextract` 默认仅包含高敏感凭据类规则；邮箱、内网 IP、linkfinder 等须显式注册。
- GeoIP `Init` 仅读取本地资源；`Update` 须提供明确的 `DataSource`。规则与字典也必须显式配置，不提供隐式用户目录初始化。

重试、响应体所有权、关闭约束及完整默认值以 [API 与配置](API.md) 为准。
