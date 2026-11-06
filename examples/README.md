# Netloom 示例

使用 [go.mod](../go.mod) 要求的 Go 版本，在仓库根目录运行这些程序。每个程序只接受一个 URL，并会发起真实网络请求。仅访问已获授权的目标；下列 `example.com` 命令要求外网 DNS 和网络访问可用。

| 示例 | 命令 | 演示内容 |
| --- | --- | --- |
| [缓冲请求](request/main.go) | `go run ./examples/request https://example.com` | `Send`、显式 TLS 验证、禁用重试、输出状态/正文大小/截断标志 |
| [流式响应](stream/main.go) | `go run ./examples/stream https://example.com` | `SendStream`、将正文复制到标准输出、由调用方关闭正文 |
| [任务 Pipeline](pipeline/main.go) | `go run ./examples/pipeline https://example.com` | 单个任务、调用 `Context.Next` 的处理器、元数据与持续读取结果通道 |

三个示例都在正常结束时关闭 Engine，并显式启用 TLS 验证。缓冲示例禁用重试；Pipeline 示例使用运行时默认配置，因此保留默认重试策略。流式示例直接输出响应字节，不输出状态信息；避免在敏感终端直接显示不可信正文。

运行时的直接拨号策略拒绝回环、未指定和链路本地地址，因此把 URL 改为本地测试服务并非受支持的绕过方法。这些示例不配置代理、不安装证书、不跟随重定向，也不初始化规则或数据资源。它们是调用演示，不是完整集成测试套件。

只编译、不发送请求：

```sh
go build ./examples/...
```

编译成功不代表真实网络行为通过。安装、配置、取消与所有权说明从[项目 README](../README.md) 与 [API 参考](../docs/API.md) 开始阅读。
