# 流式上传与请求契约

根包普通请求支持 `Request.Body []byte` 或 `Request.Upload *Upload`，两者互斥。`Raw` 不接受 Upload 或 Auth。接口不读文件路径、不持久化正文。结构化输入仍有原来的大小和头部安全限制，native reader 能力不放宽它们。

## Reader 与长度

```go
source, err := netloom.NewUpload(reader, -1) // reader 是 io.ReadCloser；未知长度
if err != nil { return err }
response, err := engine.Send(ctx, &netloom.Request{
    Method: "POST", URL: "https://upload.example/data", Upload: source,
})
```

- 长度为 `-1` 表示未知，HTTP/1.1 使用 transport 决定的 chunked framing；H2 使用 DATA 帧。非负长度是发送的精确上限，0 表示空正文。超长 reader 只发送声明的前缀，不额外读取；短于声明长度返回错误。`ErrUploadLength` 可用 errors.Is 检查，传输层也可能先返回自己的长度错误。
- NewUpload 不读取正文；首次真正打开后移交所有权，每个打开的 reader 在正常结束、错误或取消时 Close 一次。预检失败时未打开的 reader 仍属调用方。单次源一经领取不能再次 Send，也不能并发共享发送。
- reader 的 Close **必须能够中断并发阻塞的 Read**；自定义 opener 必须遵守传入 context。SDK 无法终止不合作的用户代码，不为每次阻塞读取创建遗留 goroutine。
- `NewReplayableUpload(length, opener)` 每次调用 opener 获取新的 reader。opener 必须线程安全，返回相同内容，不能依赖 SDK 自动 seek 或把正文全部缓存。开流错误经发送路径返回；关闭保证执行，但 transport 在发送完成后的 Close 错误不保证作为请求失败返回。SDK 不保证能恢复已产生的服务器副作用。
- 同一个源适用于 Send、Run 和 SendStream。SendStream 仅流式交付响应，不代表 SDK 会重试已交付的响应流；响应 Body 仍须 Close。

## Multipart

`NewMultipartUpload([]UploadPart)` 返回 source 和包含固定 boundary 的 Content-Type。每个 part 提供 Name、可选 FileName/ContentType 和 Body *Upload；不接收文件路径。顺序按 parts 数组，实际 reader 顺序懒打开，不缓冲文件内容。所有 part 长度已知时计算完整长度（包括 framing），否则未知；只有全部 part 可重放，整个 multipart 才可重放。重新打开沿用同一 boundary。

构造时复制元数据，校验头部注入/媒体类型并限制 part 数量及元数据大小。正文读取、取消或 Close 会停止生产者并关闭当前打开的 part；尚未打开的 part 不自动消费或关闭。不要把同一个 one-shot part 用于多个位置。

## 重放与重定向

- 单次源不会自动重试；显式允许 POST 重试也不能越过不可重放限制。
- 保留正文的 307/308（及其他不改方法的跳转）需要可重放源，否则返回最后的跳转响应和 ErrBodyNotReplayable，不发送下一跳。
- POST 的 301/302 及非 HEAD 的 303 改 GET，清空 Body/Upload 和正文 framing 头，不重放原源。
- Digest/认证挑战也需要新的 reader；不能重放时保留挑战响应并返回明确错误。
- 跨 origin 清除 Auth、Authorization、Cookie、自定义 TLS 等凭据；可重放正文不会因此自动脱敏。敏感正文的跨 origin 跳转应由 RedirectPolicy.ValidateURL 拒绝。

## 有界上传证据

`CaptureRequestBody` 是显式选择的字节上限，0 默认不捕获，最大 1 MiB。它只截取 application reader 的前缀，不改变发送大小、不读取第二遍、不等同于 TCP/TLS wire dump。Response.UploadEvidence 是复制的快照，包含 Prefix、BytesRead 和 Truncated；流式响应在交付响应头时冻结，不随后台读取修改。凭据和文件内容可能包含在前缀中，调用方须授权、保护和清理这些证据。

## 普通与 Raw

普通请求方法/URL/头字段遵守 HTTP 语法：拒绝控制字符、无效字段名、大小写重复字段名、歧义 Host/Content-Length 和手动 Transfer-Encoding；Content-Length 必须与已知源长度一致，实际 framing 由 transport 产生。Host 作为协议字段处理，不把 URL/dial/SNI/origin 改成 Host。HeaderOrder 只包含合法字段名，不能借特殊元字段绕过规范化。请求诊断头中的 Authorization、Proxy-Authorization、Cookie 值脱敏。

Raw 保留字节保真：只使用 URL 选择受保护的 HTTP/HTTPS socket，原始方法、目标、Host、framing、换行和正文不修复、不应用 CookieJar、Auth、multipart 或自动重定向。仍受地址防护、代理拒绝、超时/取消与响应读取上限约束；不因字节保真允许结构化输入绕过安全限制。Raw 不自动重试，避免把一个字节串中的多次操作重复执行。Raw 不提供 UploadEvidence，原始输入字节由调用方管理。
