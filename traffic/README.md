# HTTP 流量分析

`github.com/emhha/netloom/traffic` 把主动请求与 MITM 转发接到 `passive.Registry`。注册一次工具，再按入口选择插件。Engine、HTTP Server、CA 和上游传输的生命周期由调用方管理。

## 接入

```go
registry, err := passive.New([]passive.Plugin{
    infoextract.New(),
}, 128)
if err != nil {
    return err
}
flow, err := traffic.New(traffic.Config{
    Engine: engine, Registry: registry,
    Project: "example", SessionID: "authorized-session",
    Proxies: traffic.ProxyConfig{Default: sharedProxy, MITM: mitmProxy},
    OnReport: handleReport,
})
if err != nil {
    return err
}
defer flow.Close()

response, report, err := flow.Send(ctx, request, traffic.RequestOptions{})
// 同时处理 response、report 和 err，传输错误仍可能带有部分响应。
```

上例的 `infoextract` 来自 [`passive/plugins/infoextract`](../passive/plugins/infoextract/README.md)。`engine`、`ctx`、`request`、`handleReport` 与可选的代理配置由调用方提供。`Send` 同步返回分析报告。`SendStream` 保留调用方读取并关闭 `Body` 的方式，报告经 `OnReport` 交付。`PrepareTask` 在任务副本上加入代理 mutator 和通用 Handler，把成功响应接到 `Engine.Run` 原有分析链。每个任务准备一次，再交给 `Run` / `Submit`。`RequestPlugins` 和 `MITMPlugins` 分别选插件 ID，nil 使用 Registry 已注册的全部插件，空列表关闭该入口的插件执行。

MITM 使用 `flow.NewMITMBackend(checkTarget, transport)` 构建后端，再传给 `mitm.New(authority, backend, options)`。`checkTarget` 是调用方的目标策略。显式提供 `*http.Transport` 时 SDK 克隆它，并应用已选择的代理。nil 使用标准 HTTP 传输，验证上游 TLS 证书，转发时保留内容编码。自定义目标地址约束或 TLS 行为可由自己的 Backend 实现，再调用 `WrapMITM`。此时上游代理也由该 Backend 管理，`WrapMITM` 会拒绝同时存在的 `MITM` 或 `Default` 设置。HTTP Server 停止后关闭 MITM、关闭在途响应体，调用内置 Backend 的 `CloseIdleConnections`，然后调用 `traffic.Close` 排空报告。回调应尽快返回，不能在其内部调用 `Close`。

## 代理选择

主动请求按 `RequestOptions.Proxy` → 非空 `netloom.Request.Proxy` → `Proxies.Request` → `Proxies.Default` 选择。内置 MITM Backend 按 `Proxies.MITM` → `Proxies.Default` → 自带传输的代理设置选择。指针为 nil 表示继承，指向空字符串表示显式直连。配置代理失败会返回错误。原生 `Engine` 和 `mitm.New` 的配置方式继续可用。

主动入口支持 Engine 的代理协议。内置 MITM Backend 支持 HTTP、HTTPS、SOCKS5 和 SOCKS5H。共享默认代理应选两边都支持的协议。MITM 客户端的入站认证仍由 `mitm.Options` 设置。

## 采集与缓存

- 每次被接入的交换至多提交一次分析。缓冲响应在返回时分析。流式响应边读边保留正文前缀，超过上限、读到 EOF、读取失败或关闭时提交。`ResponseTruncated` 表示采集或解码达到上限，`ResponseIncomplete` 表示提交前的正文读取未完成。如果报告已因达到上限而提交，后续传输状态从响应正文的读取错误或运行时流状态取得。
- 请求和响应各默认采集 128 KiB，最大可设 1 MiB。主动上传只复用 `Request.CaptureRequestBody` 显式启用的证据。按响应头解码采集到的副本时也使用同一上限，解码错误可从报告读取。原始响应和转发字节按所选传输的契约交付。
- 异步报告使用一个 worker，默认等待队列容量为 32，默认插件 context 超时为 5 秒。队满只丢弃分析，`Dropped()` 可读到累计次数。同步 `Send` 使用调用方 context 并受同一分析超时约束。插件须遵守 context；关闭时会等待已接纳的分析和回调完成。
- 每次已接纳的交换会进入 Registry。`infoextract` 默认按项目、会话、URL、媒体类型和长度去重。命中时跳过正文提取，也不会重新返回发现。响应头独立去重，规则更新会清除之前的标记。等长正文更新可能被略过，需要区分时设置插件的 `HashBodyForCache: true`。压缩副本目前仍在插件执行前解码。其他插件的策略见 [缓存策略](../passive/plugins/README.md#缓存策略)。
- `infoextract` 在缓存未命中时先用 AC 匹配触发词，再对候选规则执行正则。无触发词的规则继续走正则。`Serialization` 也有自己的 AC 预筛选，自定义插件可选择适合自己的算法。`infoextract` 对 JS 的分析仍受提取器自己的 100 KiB 上限约束。

HTTPS 解密式 MITM 会建立新的上游 TLS 连接，上游握手由 Backend 决定。主动请求保留 Engine 的 `Request.Profile` 语义。工具读取采集副本，异步分析与响应转发分开。
