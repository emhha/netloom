# 网络空间测绘数据源

`mapping` 查询 FOFA、Hunter 和 360Quake，将响应转换为 `Result`。本包不扫描返回的目标、不持久化资产、不聚合多数据源，也不跨数据源去重。`Engine` 通过 `Name`、`Search`、`ConvertQuery` 提供接口，编排由调用方负责。

## 构造与凭据

传入非 nil 的 HTTP 客户端，以及实现 `SecretReader.Get(context.Context, string) ([]byte, error)` 的凭据读取器。[httpclient](../httpclient/README.md) 会话提供所需的 GET/POST 方法：

```go
session := httpclient.NewSession(httpclient.Options{DisableRetries: true})
defer session.Close()
engine := mapping.NewFofaEngine(session, secrets, "")
results, err := engine.Search(ctx, engine.ConvertQuery("example.com"), 100)
```

分别导入 `github.com/emhha/netloom/httpclient` 和 `github.com/emhha/netloom/mapping`；`secrets` 和 `ctx` 由调用方提供。禁用重试可避免自动重复可能收费的请求。

| 构造函数 | 凭据键 | 端点选择 |
| --- | --- | --- |
| `NewFofaEngine` | `fofa_key`，可选 `fofa_email` | 空端点使用 FOFA 搜索 API |
| `NewHunterEngine` | `hunter_key` | 空端点使用 Hunter 搜索 API |
| `NewQuakeEngine` | `quake_key` | 内置 Quake 服务搜索 API |
| `NewQuakeEngineAt` | `quake_key` | 调用方指定端点 |

每次搜索重新读取凭据、去除首尾空白并发送给数据源。读取器为 nil、读取失败或键值为空时返回 `ErrEngineNotConfigured`，不传播原始凭据读取错误。本包不解密、保存或供应凭据。覆盖端点时必须信任该端点，因为凭据会发送到所选地址。并发调用须提供并发安全的凭据读取器和 HTTP 客户端。

## 查询与结果语义

`Search` 接收数据源原生查询语法，不自动调用 `ConvertQuery`。`ConvertQuery` 仅用于将普通 IP 或域名转换成查询，不是通用查询语言翻译器。Quake 会去除输入首尾空白；FOFA/Hunter 调用方应在转换前自行处理。

非正数 limit 默认请求 100 条。FOFA/Hunter 将上限限制为 1,000 条；Quake 每页最多 100 条。一次搜索可能发起多次请求并消耗数据源配额。上下文取消与传输重试行为取决于注入的 HTTP 客户端。数据源错误作为错误返回，不伪装成成功的空数据集。

`Result` 按数据源可用字段提供端点/地址、标题、地域、组织、组件和来源。上游缺失字段保持零值，不保证记录完整或唯一。协议可能不是 HTTP，不能假设每条结果都可作为 HTTP URL 打开。API 响应体使用 HTTP 客户端的有界 `ReadBody` 辅助函数读取。

## 限制与验证

适配器依赖上游响应格式、访问权限、配额和查询语法；不验证账号权益，也不保证本地限流值符合订阅限制。未宣称通过真实付费服务验收。

本包当前没有包内测试文件；`go test ./mapping` 仅检查编译，不代表协议覆盖。修改分页或响应映射前应补充本地夹具测试；真实服务检查须取得明确授权并提供凭据。
