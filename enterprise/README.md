# 企业工商数据源

`enterprise` 定义公司摘要、投资树节点、关联资产表和 `Provider` 接口，内置百度爱企查查询实现。不提供服务端注册表、凭据保险库、递归投资树编排、数据库或浏览器自动化。

## 使用

```go
session := httpclient.NewSession(httpclient.Options{DisableRetries: true})
defer session.Close()
provider := enterprise.NewAiqichaProvider(session, secrets)
companies, err := provider.SearchByName(ctx, "示例公司")
```

分别导入 `github.com/emhha/netloom/httpclient` 和 `github.com/emhha/netloom/enterprise`。`ctx` 和 `secrets` 由调用方管理。凭据读取器须实现 `Get(context.Context, string) ([]byte, error)`，为 `aiqicha_cookie` 返回明文 Cookie 字节。HTTP 客户端须实现 `Get(context.Context, string, string, map[string]string) (*http.Response, error)`；标准 Netloom HTTP 会话满足此接口。

`NewAiqichaProviderAt` 接受显式端点，用于受控部署或本地夹具。必须传入非 nil HTTP 客户端。端点选择涉及信任边界，因为数据源适配器会向该端点发送 Cookie。

## 操作与所有权

- `SearchByName` 返回 `CompanyBasic` 摘要和数据源公司标识。
- `GetCompanyDetail`、`GetSubsidiaries`、`GetBranches` 返回公司节点与关系。遍历深度、聚合和持久化由调用方决定；`EnterpriseTree` 只是模型，不会自行抓取整棵树。
- `FetchTable` 接受 `icp`、`wechat`、`app`、`copyright`。凭据校验后，不支持的字段返回 nil 表与 nil 错误；解引用前须判断结果是否为 nil。

每次公开查询都会重新读取 Cookie，支持调用方轮换。读取器为 nil、读取失败或 Cookie 为空时返回 `ErrNotConfigured`。凭据存储、加解密、获取、续期与日志策略由调用方负责。使用期间不要修改数据源依赖；并发调用须提供并发安全的实现。

响应通过 [httpclient.ReadBody](../httpclient/README.md) 读取并关闭，受其 8 MiB 上限约束。网络取消、按数据源限流与重试由注入的客户端提供。不能接受重复请求或额外配额消耗时，应禁用自动重试。

## 错误与兼容限制

适配器提供 `ErrNotConfigured`、`ErrSecurityVerify`、`ErrIPBanned`、`ErrCookieExpired`，可使用 `errors.Is` 判断包装后的错误。其他 HTTP、解析和数据源业务错误正常返回。不自动处理验证码、登录、代理轮换或 Cookie 刷新；验证挑战与访问规则由调用方处理。

爱企查端点和响应格式可独立于本库变化。结果是数据源报告的快照，不保证法律归属或完整性。使用授权凭据并遵守相应数据源条款。

## 验证

在仓库根目录运行 `go test ./enterprise` 和 `go test -race ./enterprise`。现有测试使用本地 HTTP 夹具，覆盖代表性的搜索、详情、关系、表格、错误响应及 JSON 字段名，需要允许绑定回环 socket。测试不证明真实爱企查访问、当前响应格式兼容或验证挑战处理成功。
