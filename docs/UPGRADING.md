# 升级说明

## 当前开发版本

### 公开导入路径

统一使用 module `github.com/emhha/netloom`，根包标识符为 `netloom`，子包位于同一 module 下。使用早期裸路径 `netloom` 的代码应更新 module 依赖及导入路径，例如：

```go
import "github.com/emhha/netloom"
import "github.com/emhha/netloom/httpdata/netloomdata"
```

不提供旧 module 路径的兼容包。安装方式见 [安装与使用](MIGRATION.md)。

### 默认值与可见行为

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
