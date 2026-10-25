# netrt

独立 Go 网络 SDK，临时模块路径 `netrt.local/netrt`，Go 1.26.0+。
核心支持 HTTP/HTTPS、TLS 指纹、自定义 CA/mTLS、代理、Raw、流式响应、Cookie、重定向、Pipeline、调度、限流与取消。

```go
engine, err := netrt.New(netrt.Config{Retries: -1})
if err != nil { return err }
defer engine.Close()
response, err := engine.Send(ctx, &netrt.Request{
    URL: "https://example.com", VerifyTLS: true,
})
```

`Send` 返回已读取并关闭的响应；`SendStream` 的 `Body` 必须关闭。`Engine.Close` 取消工作并等待退出。
兼容来源默认值：`Retries=0` 表示重试两次，负数禁用；根包的 TLS 验证须显式开启。
直接拨号拒绝回环、未指定和链路本地地址，允许私网；代理负责代理出口的地址策略。

| 包 | 用途 |
| --- | --- |
| 根包 | 网络运行时、重定向、TLS、Pipeline |
| `httpdata` | 不依赖网络运行时的离线快照 |
| `httpdata/netrtdata` | 显式复制运行时结果为离线快照 |
| `fingerprint`、`infoextract` | 指纹与信息提取 |
| `passive`、`passive/plugins` | 被动分析及内置插件 |
| `probe`、`dirscan` | 探活与目录扫描 |
| `nethttp` | 纯 cURL 解析和结构化请求转换 |
| `mitm` | 内存 CA、CONNECT、转发和有界观察回调 |

指纹规则保存在 [`fingerprint/rules`](fingerprint/rules/README.md)，通过 `fingerprint.Config{RulesDir: "fingerprint/rules"}` 加载该目录的 `sources.json`：默认禁用 webfinger，启用 EHole（958 条）、FingerprintHub v4（3,425 个模板）及原有 Wappalyzer（7,540 项技术）。各格式均由本库自行解析，不依赖它们的扫描 SDK；零值配置不读取文件。
`MatchExchange(ctx, request, response)` 可按实际请求的方法、路径和请求头匹配 FingerprintHub 探针约束，不会主动发送请求。
EHole/FingerprintHub 使用 AC 批量匹配、哈希索引及安全的正则预筛选；[性能记录](docs/PERFORMANCE.md) 包含可复现基准与结果一致性验证。
目录扫描通过 `dirscan.Config.Wordlist` 或 `WordlistDir` 提供字典；不初始化用户目录。仓库附带 [固定 Git 版本的 dirsearch 字典](dirscan/wordlists/README.md)，可显式指定 `WordlistDir: "dirscan/wordlists/dirsearch/db"`，不 embed 到二进制。
MITM 不自动监听或安装证书，私钥的保管由调用方负责。

运行示例：`go run ./examples/request https://example.com`，另有 `examples/stream`、`examples/pipeline`。

验证：`go test ./...`、`go vet ./...`、`go test -race ./...`。
流式与 Python 服务测试使用 `go test -tags=integration ./...`；Python 测试另需外部服务与 DNS 配置，见测试注释。
当前沙箱的 TCP socket 限制及实际验证结果见 [验证记录](docs/VALIDATION.md)。

适用许可保留于 [LICENSE](LICENSE)，发布前须完成代码与资源的来源权利核实。
