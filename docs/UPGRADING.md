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
- MITM 默认 CA CommonName 为 `netloom MITM CA`，代理认证 Realm 为 `netloom`。自定义名称通过 `AuthorityOptions.CommonName` 和代理选项配置；加载已有 PEM 不会修改证书名称。
- 企业信息包凭据缺失返回 `ErrNotConfigured`，错误说明指向凭据读取接口及 `aiqicha_cookie` 键。判断错误应使用 `errors.Is`，不要依赖提示文本。
- `infoextract` 默认仅包含高敏感凭据类规则；邮箱、内网 IP、linkfinder 等须显式注册。
- GeoIP `Init` 仅读取本地资源；`Update` 须提供明确的 `DataSource`。规则与字典也必须显式配置，不提供隐式用户目录初始化。

重试、响应体所有权、关闭约束及完整默认值以 [API 与配置](API.md) 为准。
