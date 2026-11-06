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

- 零值配置使用 30 秒 HTTP 客户端超时、初次请求后最多三次重试，以及一秒重试等待。正数 `RetryMax` 覆盖重试次数；`DisableRetries: true` 或负数 `RetryMax` 禁用重试。
- 网络错误、HTTP 429 和 HTTP 5xx 会触发重试，POST 也不例外。付费查询或不能安全重复的操作应禁用重试。最后一次 429/5xx 响应交由调用方检查；网络失败耗尽重试后包装 `ErrRetryExhausted`。
- HTTP 429 支持 `Retry-After` 的秒数或 HTTP 日期，等待上限为 60 秒。取消上下文会中断重试与限流等待。需要限制整个操作耗时时，应设置上下文截止时间，而不只依赖单次 HTTP 请求超时。
- 可能重试时，`Do` 要求正文可重放，即设置 `Request.GetBody`。不要并发复用或修改同一个请求及请求头。
- 默认验证 TLS 证书；`InsecureSkipVerify` 会关闭验证并记录警告。支持 HTTP/HTTPS、SOCKS5/SOCKS5H 代理 URL。无效或不支持的代理会记录日志后被忽略，并回退到直连；要求代理配置失败时拒绝连接的调用方必须在构造前自行校验。
- 不自动跟随重定向，重定向响应原样返回。不提供 CookieJar 或凭据存储。

## 限流与生命周期

所有会话共享进程内令牌桶，以完整数据源字符串为键；重试也消耗令牌。默认 FOFA/Quake 每秒 1 次、Hunter 每秒 15 次、Aiqicha/Tianyancha/Kuaicha 每 3 秒 1 次、Riskbird 每 5 秒 1 次，其他名称每秒 5 次。这些本地默认值不保证满足账号配额，也不是跨进程限流器。

会话支持并发请求。`Close` 仅释放传输层空闲连接，不取消正在执行的工作，也不永久禁用会话。终止活动请求应取消其上下文。

## 验证

在仓库根目录运行 `go test ./httpclient` 和 `go test -race ./httpclient`。测试使用本地 HTTP 监听，不需要真实数据源凭据，但要求允许绑定回环 socket；它们不证明真实服务兼容性。
