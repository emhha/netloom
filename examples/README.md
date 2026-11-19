# Netloom 示例

使用 [go.mod](../go.mod) 要求的 Go 版本，在仓库根目录运行。前三个程序各接受一个 URL，连接调用方选择的目标。下列 `example.com` 命令要求外网 DNS 和网络访问可用。流量分析示例只连接本机测试服务。

| 示例 | 命令 | 演示内容 |
| --- | --- | --- |
| [缓冲请求](request/main.go) | `go run ./examples/request https://example.com` | `Send`、显式 TLS 验证、禁用重试、输出状态/正文大小/截断标志 |
| [流式响应](stream/main.go) | `go run ./examples/stream https://example.com` | `SendStream`、将正文复制到标准输出、由调用方关闭正文 |
| [任务 Pipeline](pipeline/main.go) | `go run ./examples/pipeline https://example.com` | 单个任务、调用 `Context.Next` 的处理器、元数据与持续读取结果通道 |
| [流量分析](traffic/main.go) | `go run ./examples/traffic` | 导入 curl 请求、启动 HTTPS MITM、共用代理和插件、查看报告与去重 |

三个示例都在正常结束时关闭 Engine，并显式启用 TLS 验证。缓冲示例禁用重试；Pipeline 示例使用运行时默认配置，因此保留默认重试策略。流式示例直接输出响应字节，不输出状态信息；避免在敏感终端直接显示不可信正文。

前三个示例使用运行时的直连策略，拒绝回环、未指定和链路本地地址。

## 流量分析示例

`go run ./examples/traffic` 会启动本地 TLS 源站、固定目标的上游代理和 MITM 监听。它用 `nethttp.ParseCurl` 导入一条请求，再让模拟浏览器的标准库客户端经 MITM 请求同一份合成 JS。两条路径共用上游代理、`infoextract` 和 `serialization` 插件。输出先显示 `request` 的 `demo_marker` 发现，再显示 `mitm` 的 `body_cache_hit: true`。后者表明正文已检查，旧发现不会再报告。示例只输出规则名和报告状态，TLS 信任局限于进程内的测试客户端。

只编译、不发送请求：

```sh
go build ./examples/...
```

编译成功不代表真实网络行为通过。安装、配置、取消与所有权说明从[项目 README](../README.md) 与 [API 参考](../docs/API.md) 开始阅读。
