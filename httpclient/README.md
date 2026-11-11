# HTTP API 客户端

`httpclient` 使用 Go 标准库提供可复用的第三方 API 查询会话，与 Netloom 扫描运行时独立：不提供 TLS 指纹、任务 Pipeline 或根包的拨号防护。端点授权与网络访问策略由调用方负责。

## 使用

导入路径为 `github.com/emhha/netloom/httpclient`。

```go
session := httpclient.NewSession(httpclient.Options{DisableRetries: true})
defer session.Close()
response, err := session.Get(ctx, endpoint, "fofa", headers)
if err != nil {
    return err
}
body, err := httpclient.ReadBody(response)
```

示例中的 `ctx`、`endpoint` 和明文 `headers` 由调用方提供。`Get`、`Post`、`Do` 不会仅因 HTTP 状态失败就返回 Go 错误；须同时检查传输错误与状态码。调用方负责关闭每个返回的响应体；`ReadBody` 对正文设置 8 MiB 上限，超限报错，失败时也会关闭正文。直接读取响应体不受此辅助函数的大小限制。

## 配置与重试

- 零值配置使用 30 秒 HTTP 客户端超时、符合下述重试条件时初次请求后最多三次重试，以及一秒重试等待。正数 `RetryMax` 覆盖重试次数；`DisableRetries: true` 或负数 `RetryMax` 禁用本包的自动重试循环，无论方法白名单如何配置。
- `RetryMethods: nil` 默认仅允许 `GET`、`HEAD`、`OPTIONS`；非 nil 空切片不允许任何方法自动重试。构造时复制该切片，仅接受大写 HTTP token，忽略非法或小写项；请求方法精确匹配，不隐式转大写，仅空方法按标准库默认 `GET` 处理。`POST` 等其他方法必须显式列入，例如 `RetryMethods: []string{"POST"}`；这代表调用方确认该操作可重复，并非 SDK 对业务幂等的保证。
- 只有方法获准且正文可重放时，网络错误、HTTP 429 和 HTTP 5xx 才会触发本包重试。最后一次 429/5xx 响应交由调用方检查；网络失败耗尽后包装 `ErrRetryExhausted` 并保留原始错误链，即使有效重试次数为零也保留此错误分类。
- HTTP 429 支持 `Retry-After` 的秒数或 HTTP 日期，等待上限为 60 秒。取消上下文会中断重试与限流等待。需要限制整个操作耗时时，应设置上下文截止时间，而不只依赖单次 HTTP 请求超时。
- `Post` 的字节正文可重放；`Do` 有正文时要求设置 `Request.GetBody` 才能自动重试。nil 或 `http.NoBody` 也可重放；其他正文未提供 `GetBody` 时只允许首次发送，不重复使用已消费的 reader。`GetBody` 返回错误立即停止并保留错误链，不再发送。当前 `Do` 在首次发送时也调用 `GetBody`；该路径下原始 `Request.Body` 不会被消费或自动关闭，调用方应负责关闭它，各次重放生成的正文由 HTTP 传输关闭。不要并发复用或修改同一个请求及请求头。
- 默认验证 TLS 证书；`InsecureSkipVerify` 会关闭验证并记录警告。支持 HTTP/HTTPS、SOCKS5/SOCKS5H 代理 URL。仅空字符串明确使用直连；非空无效代理（包括空白字符串）不会回退到直连。`NewSession` 保留原签名，可用 `session.Err()` 在构造后检查；`Get`、`Post`、`Do` 在限流、正文重放及发送前返回稳定的 `ErrInvalidProxy`，不重试、不记录代理 URL 或凭据。不支持的 scheme 同时支持 `errors.Is(err, ErrUnsupportedProxy)`。HTTP(S) 可省略端口（80/443）；SOCKS 必须显式提供 1–65535 端口。允许 userinfo、IPv6 和根路径 `/`，拒绝非根路径、query、fragment；解析不执行 DNS 或网络访问。
- 不自动跟随重定向，重定向响应原样返回。不提供 CookieJar 或凭据存储。

方法获准、正文可重放均不代表业务或账单幂等：付费 GET 也可能因重复查询扣费。建议为不能接受重复操作或额外配额消耗的工作负载单独构造 `DisableRetries: true` 会话。`RetryMethods` 与 `DisableRetries` 只控制本包的自动重试循环；底层 Go `http.Transport` 在复用连接断开等条件下仍可能透明重发。这不是 exactly-once 保证，重复扣费及副作用仍需由调用方与上游幂等、去重和计费协议共同处理。注入其他 HTTP 客户端时，数据源适配器不覆盖其重试策略。

## 限流与生命周期

所有会话共享进程内令牌桶，以完整数据源字符串为键；重试也消耗令牌。默认 FOFA/Quake 每秒 1 次、Hunter 每秒 15 次、Aiqicha/Tianyancha/Kuaicha 每 3 秒 1 次、Riskbird 每 5 秒 1 次，其他名称每秒 5 次。这些本地默认值不保证满足账号配额，也不是跨进程限流器。

会话支持并发请求。`Close` 仅释放传输层空闲连接，不取消正在执行的工作，也不永久禁用会话。终止活动请求应取消其上下文。

## 验证

在仓库根目录运行 `go test ./httpclient` 和 `go test -race ./httpclient`。测试使用内存传输及本地 HTTP 监听，覆盖方法白名单、正文重放、错误链、响应体归属、次数与取消等，不需要真实数据源凭据；本地 HTTP 测试要求允许绑定回环 socket。它们不证明真实服务兼容性、业务幂等或计费去重。
