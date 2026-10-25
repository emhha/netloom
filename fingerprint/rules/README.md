# 指纹规则目录

`finger.yaml` 保存固定版本的生产指纹规则，与原文件逐字节相同。它从本机已有的 webfinger Git 提交对象导出，没有在导入时抓取新规则。

来源：https://github.com/jjf012/webfinger.git

固定提交：`fb89e848a7b0f2536eaf6ea95719f1b5b727fd10`。

`upstream.json` 记录提交号、原路径、Git blob 和 SHA-256；原始出处说明保留于 `README.upstream.md`。该来源检出没有 LICENSE 或明确许可声明；本目录不自行赋予这些规则新的许可证，公开发布前仍须核实再分发条件。

## 加载

在 netrt 仓库根目录运行时：

```go
engine, err := fingerprint.New(ctx, fingerprint.Config{
    RulesDir: "fingerprint/rules",
})
```

`RulesDir` 读取同目录 `sources.json`，按源选择原生解析器。当前开关：

| 来源 | 文件 | 启用 |
| --- | --- | --- |
| webfinger | finger.yaml | false |
| EHole | ehole.json | true |
| FingerprintHub v4 | fingerprinthub_v4.json | true |
| Wappalyzer | wappalyzer.json | true |

修改 `enabled` 后重新创建 Engine 即可生效；已禁用的文件不会被读取或编译。已启用的文件缺失、为空或格式不支持时构造返回错误。`RulesDir` 不能与逐文件输入混用，避免绕过开关；`Config{}` 仍不自动读取磁盘。

原有 `CustomRulesDir`、`WebfingerYAML`、`WappalyzerJSONPath` 仍可独立显式使用；另新增 `EHoleJSONPath`、`FingerprintHubJSONPath`。这些低层输入不读取 sources.json。`CustomRulesDir` 扫描第一层所有 `.yaml` 并标记 Source=custom，不适用于当前默认多源开关配置。

其他应用部署时把该目录作为资源复制到自己的部署目录，配置实际路径；规则不 embed 到 SDK 二进制。

自己的规则可保存在独立目录，以同样的 `CustomRulesDir` 配置加载；如需与上游规则一起使用，把所需 `.yaml` 放到同一个调用方管理的目录。支持的格式：

```yaml
my-app:
    - header="X-Powered-By: my-app"
    - body="my-app-login"
```

## Wappalyzer 规则

`wappalyzer.json` 是完整规则文件，包含 7,540 项技术，原样取自 projectdiscovery/wappalyzergo 的 fingerprints_data.json，固定提交 `efb75ceb931f003b6c224d414fb0cba3116c0b08`，替换原来的空测试夹具。

来源：https://github.com/projectdiscovery/wappalyzergo 。`wappalyzer.upstream.json` 记录提交、文件路径和 SHA-256；原始项目 README 与 MIT 许可分别保留于 README.wappalyzergo.md、LICENSE.wappalyzergo.md。本次 GitHub 连接器及直接下载均因网络不可用而失败，因此从本机已有 Git 提交对象导入，不宣称远端最新版。

使用 `WappalyzerJSONPath` 显式加载；`CustomRulesDir` 只读取 YAML，不会自动加载这个 JSON。当前离线解析器支持 headers/cookies/html/scripts/scriptSrc/meta/implies 等字段，不执行浏览器 JavaScript 或主动探测；数据文件中其他字段保留，但不代表全部检测能力均已实现。

## EHole 与 FingerprintHub

两份 JSON 由用户下载提供，本次保持字节不变。`native-sources.upstream.json` 记录源 URL、文件名、规则数及 SHA-256；没有获知源提交号，未臆造版本或许可。

- EHole：https://github.com/EdgeSecurityTeam/EHole/blob/main/finger.json ，958 条。原生 cms/method/location/keyword 格式；同一规则的关键词全部满足，不同规则为备选。keyword 忽略大小写，regular 使用 Go 正则，支持 body/header/title 和已捕获 favicon 的 mmh3。header 按其格式使用 JSON 序列化。
- FingerprintHub：https://github.com/0x727/FingerprintHub/blob/main/web_fingerprint_v4.json ，3,425 个模板（本地名 fingerprinthub_v4.json）。自行解析 http/matchers；支持 word/regex/favicon、and/or、case-insensitive、negative、MD5/mmh3 图标哈希及 regex 版本提取。未知匹配类型及无效正则返回明确错误。

推荐 `engine.MatchExchange(ctx, request, response)`：按已捕获请求约束 method/path/headers/body，满足条件才匹配对应探针；passive 指纹插件已接入此接口。没有请求元数据时只允许普通 GET/通用首页规则，特定路径、POST 和自定义请求头规则不会被当成普通首页证据；可通过 Response.URL 提供响应路径。

不发送任何探针、下载图标或执行规则程序。MD5 图标值由调用方填入 httpdata.Response.FaviconMD5，mmh3 使用 FaviconHash；缺失图标证据不会变成 negative 命中。截断正文不能证明 negative 正文条件。raw 请求与 TCP、JSON 提取器不在当前被动匹配契约内；用户提供的完整 v4 文件可成功加载，其 nginx 正则版本提取已实现。

## 性能

每个规则源均有独立入口文件：webfinger.go、ehole.go、fingerprinthub.go、wappalyzer.go。webfinger.go 中的 WebfingerMatcher / LoadWebfingerYAML 负责 YAML 加载、AC 与图标索引和匹配；lexer/parser/ast/compiler 等文件保留底层实现，Engine 只协调各源。

EHole 和 FingerprintHub 在加载时建立按字段、大小写模式划分的 AC 索引，使用紧凑双数组保存状态；正文批量扫描后只验证候选规则。图标哈希直接查询索引；正则会先核对可确定必需的字面量，无法安全提取时仍执行原正则。重复的请求约束只检查一次，正文标准化结果仅在当前匹配调用内复用，可并发共享 Engine。

这些索引增加一次性的构建成本，建议复用 Engine。匹配语义、启用开关和规则文件不变；新旧实现对照测试及实测数据见 [性能记录](../../docs/PERFORMANCE.md)。
