# 升级说明

## 当前开发版本

### 公开导入路径

统一使用 module `github.com/emhha/netloom`，根包标识符为 `netloom`，子包位于同一 module 下。使用早期裸路径 `netloom` 的代码应更新 module 依赖及导入路径，例如：

```go
import "github.com/emhha/netloom"
import "github.com/emhha/netloom/httpdata/netloomdata"
```

不提供旧 module 路径的兼容包。安装方式见 [安装与使用](MIGRATION.md)。

### 默认值与可见行为

- 根包 `Request.VerifyTLS` 默认 false，验证证书须显式启用。`Config.Retries=0` 表示默认重试两次，负数禁用重试；路径调整不改变这些行为。
- Send/Run 的配置超时不再被底层隐式 10 秒总期限覆盖；SendStream 现在也遵守 Config.Timeout。优先级为正值 Request.Timeout > Config.Timeout > 默认 10 秒，调用方更早的 context deadline 仍有效。TCP 拨号超时暂保持 10 秒。
- Send 在失败时可同时返回非 nil Response 与 error；Run 失败结果保留已收到的 headers/body。重试耗尽时响应是最近一次非 nil 证据，错误为最终失败原因，可能来自不同尝试；调用方必须检查 error，不将部分正文当作成功。
- 缓冲与流式请求只返回实际连接可获得的 TLS 元数据，不再隐式第二次握手；部分后端下 TLS 字段可能由过去的补探测值变为 nil。普通缓冲响应新增实际 trace timings，缺失阶段保留 nil。
- StreamResponse 新增 Status() 与 StreamStatus 完成快照；Response 保持响应头时元数据，不在后台更新。提前关闭且未观察 EOF 时 Status.Error 为 ErrStreamClosedEarly（取消和读取错误保留相应原因）；EOF 后仍须 Close。详情见 [API 与配置](API.md)。
- MITM 默认 CA CommonName 为 `netloom MITM CA`，代理认证 Realm 为 `netloom`。自定义名称通过 `AuthorityOptions.CommonName` 和代理选项配置；加载已有 PEM 不会修改证书名称。
- 企业信息包凭据缺失返回 `ErrNotConfigured`，错误说明指向凭据读取接口及 `aiqicha_cookie` 键。判断错误应使用 `errors.Is`，不要依赖提示文本。
- `infoextract` 默认仅包含高敏感凭据类规则；邮箱、内网 IP、linkfinder 等须显式注册。
- GeoIP `Init` 仅读取本地资源；`Update` 须提供明确的 `DataSource`。规则与字典也必须显式配置，不提供隐式用户目录初始化。

重试、响应体所有权、关闭约束及完整默认值以 [API 与配置](API.md) 为准。
