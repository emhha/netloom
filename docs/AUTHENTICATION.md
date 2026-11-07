# 显式请求认证

根包 `Request.Auth` 仅控制当前逻辑 origin 的认证。不从 URL、环境、用户目录或文件发现凭据，不缓存凭据、Digest nonce 或 Authorization，不处理代理认证，也不引入凭据持久化。

## Basic 与 Digest

```go
request := &netloom.Request{
    URL:       "https://service.example/private",
    VerifyTLS: true,
    Auth: &netloom.AuthOptions{
        Scheme:   netloom.AuthDigest,
        Username: "account",
        Password: passwordFromCaller,
    },
}
response, err := engine.Send(ctx, request)
```

- `AuthBasic` 是显式、预先发送的 Basic；Base64 不是加密，应使用 HTTPS 并开启正常证书验证。用户名不能含冒号；用户名/密码必须为有效 UTF-8、无控制字符，各至多 4096 字节。
- `AuthDigest` 首次请求不带凭据，仅在当前 origin 返回 `401` 与 `WWW-Authenticate` 后生成 Authorization。支持 RFC 7616 的 MD5、SHA-256、SHA-512-256 及相应 `-sess` 变体；多个可用 challenge 优先选择较强 hash。MD5 仅为明确选择 Digest 时的兼容机制，不意味着适用于高安全性部署。
- 支持 `qop=auth`、没有 qop 的兼容模式、`charset=UTF-8`、opaque 和 stale。仅提供 `auth-int`、不支持的算法/字符集、`userhash=true` 不会被悄悄改成 Basic 或其他算法；返回 `ErrAuthUnsupported`。nonce 使用服务端 challenge，cnonce 使用密码学随机数；nonce-count 只在本次认证交换内维护。
- `MaxChallenges=0` 默认最多重放两次；显式值只能为 1 或 2。首次请求不计入重放次数。Digest 已提交凭据后，只有 `stale=true` 才进行下一次认证重放；其他再次 `401` 与达到次数上限的 `401` 作为普通 HTTP 响应保留，不伪装成网络失败。上层显式配置的请求重试策略仍有自己的预算。
- 不校验 `Authentication-Info` 的 rspauth，不提供 Digest 双向认证、auth-int 正文 hash 或跨请求 nonce 复用。

普通缓冲与流式传输共享实际请求的认证交换；严格 H2 与显式 TLS 控制仍作用于每轮真实 socket。挑战重放重新取得同一逻辑请求的正文，仅使用底层请求的 `GetBody`：字节正文和 replayable Upload 可以重放；一次性 Upload 在需要重放时返回 `ErrBodyNotReplayable`，不会悄悄发送空正文。认证不会绕过上传关闭、取消、阶段超时、单次 Timeout 或 Total 预算。

中间 `401` 的响应体直接关闭，不读取/累积挑战正文（零字节 drain 上限）；最终响应保留正文。调用方始终必须关闭流式正文。认证协议错误保留最后响应与通用错误；缓冲调用可检查响应证据，流式失败不会返回需要管理的活动正文。

## 扩展 challenge 认证

实现 `ChallengeAuthenticator`：

```go
type ChallengeAuthenticator interface {
    Authenticate(context.Context, AuthChallenge) (string, error)
}

type AuthChallenge struct {
    URL     string
    Method  string
    Header  fhttp.Header
    Attempt int
}
```

将实现赋给 `AuthOptions.Authenticator`，不要同时设置 Scheme/Username/Password。扩展只在同 origin 的 `401` 与 `WWW-Authenticate` 出现时调用，收到新复制的响应 Header，返回完整 Authorization 字段值。Attempt 从 1 开始，仍受最多两次 challenge 重放限制；不要将它理解为代理认证回调。

扩展是调用方信任边界：必须响应 context、避免自行跳转/持久化凭据，复用实例须并发安全。选项 Clone 复制值但不复制接口实现、闭包或其私有状态；请求及未关闭的流期间不得修改这些对象。扩展错误文本可能含秘密，因此运行时只返回通用 `ErrAuthChallenge`；取消原因仍保留。返回值为空、包含控制字符、首尾空白或超过 16 KiB 会被拒绝。

## 安全边界与错误

- Raw+Auth、Auth 与显式 Authorization 并用、未知 Scheme、无效凭据/次数或混合扩展与内建凭据返回 `ErrAuthOptions`。Raw 原始字节不会被认证层修改。
- 仅处理 origin `WWW-Authenticate`，忽略 `Proxy-Authenticate` 和 `407`。认证帮助器要求底层发送不自动重定向，检查请求与响应所指 origin；不向不同 scheme/hostname/port 重放凭据。`Do` 跨 origin 清除 Auth，后续目标不会继承认证选项。
- challenge 总长度至多 16 KiB、最多 16 个 challenge、每个至多 32 个参数、参数值至多 4096 字节；大小写无关的重复参数、坏引号/控制字符和非本 origin 的 domain 返回 `ErrAuthChallenge`。错误文本不包含用户名、密码、nonce 或生成的 Authorization。
- 每轮发送克隆请求 Header，不修改原始 Header 或保存生成的认证材料；响应请求头证据不包含生成的 Authorization。没有凭据缓存，连续与并发请求不会共享 Digest 计数。

这些机制不是通用浏览器登录、OAuth token 管理、NTLM/Kerberos 实现或认证代理。扩展的策略、凭据来源、更新与撤销由调用方管理。
