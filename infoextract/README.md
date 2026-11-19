# 敏感信息候选提取

`github.com/emhha/netloom/infoextract` 是可独立使用的离线 HTTP 响应分析包。它读取调用方提供的正文与响应头，不创建网络 Engine、不发送请求，也不要求通过被动分析 Registry 使用。

## 独立调用

```go
import (
    "github.com/emhha/netloom/httpdata"
    "github.com/emhha/netloom/infoextract"
)

extractor := infoextract.New()
findings := extractor.ExtractWithContentType(
    []byte(`{"token":"ghp_012345678901234567890123456789012345"}`),
    map[string][]string{"Content-Type": {"application/json"}},
    "application/json",
)
_ = findings

// 已有 httpdata 快照也可直接转为 artifacts。
artifacts, err := extractor.Extract(&httpdata.Response{
    Body: []byte("-----BEGIN RSA PRIVATE KEY-----"),
    ContentType: "text/plain",
})
_, _ = artifacts, err
```

`ExtractWithContentType` 返回 `Finding`，含 RuleName、Value、Capture、Sensitivity、Color 和 Scope；Value 是完整正则匹配，Capture 为存在时的第一个捕获组。`Extract` 返回 `httpdata.Artifact`，优先使用非空 Capture，否则使用 Value；nil 响应返回空结果。结果可能包含真实秘密，调用方负责授权、脱敏、访问控制与保留期限；命中表示敏感信息候选，不保证凭据有效。

## 共享 AC 与规则

提取器使用公共 [ac 引擎](../ac/README.md) 预筛选触发词，再对候选运行 Go RE2 正则；共享引擎不改变提取接口、正文/响应头路由或结果语义。`New` 默认只加载高敏感凭据类规则；邮箱、内网 IP、linkfinder 等不是当前内置规则，可通过 `AddRule` 显式扩展。

```go
err := extractor.AddRule(infoextract.Rule{
    Name: "example_secret",
    Pattern: `example_secret=([A-Za-z0-9]{16,})`,
    Triggers: []string{"example_secret="},
    Scope: "body",
    Sensitivity: "high",
})
_ = err
```

- `Triggers` 使用大小写敏感的字节串匹配，任一触发词命中才执行该规则正则。nil 或零长度切片表示始终运行正则的 fallback；切片中的空字符串不作为触发词，只有空字符串的非空切片永不触发（保留既有语义）。相同词可触发多个规则，后缀/重叠及重复出现不改变规则顺序。调用方必须保证每个希望检出的匹配都含有至少一个触发词；不确定时使用 nil。大小写不敏感或存在多分支的正则尤其不能随意选择单个字面量。
- `AddRule` 按 Name 替换已有同名规则；无效或空 Pattern 返回错误，不修改现有规则。省略 Scope/Sensitivity/Color 时分别默认为 `all`、`low`、`gray`。
- Scope 可选择 `body`、`header` 或 `all`。Category 为 `special` 的规则仅适用于 JavaScript/JSON 正文。
- 二进制 Content-Type 跳过正文，但仍分析响应头；JavaScript 正文只检查前 100 KiB。JSON 正文不套用该 JavaScript 前缀限制。响应头按小写头名称和各值序列化后匹配。
- 每条规则每次匹配调用最多取 257 个正则匹配；独立 API 不提供与插件相同的总体结果截断标记，不应把未命中理解为完整排除。
- 提取器可并发复用，包括并发 `AddRule`，但使用后不要复制 `InfoExtractor` 本身。规则列表按 copy-on-write 发布；每次 `ExtractWithContentType` 为正文与响应头捕获同一版本的规则和 AC 快照，不会被后续同名替换原地改写。
- `AddRule` 复制 `Triggers`，返回后调用方可复用原切片；调用期间不要并发修改传入正文、响应头或正在提交的规则切片。

## 不可变规则快照与缓存身份

需要让多次操作使用同一代规则时，显式取得快照：

```go
snapshot := extractor.Snapshot()
identity := snapshot.Identity()
findings := snapshot.ExtractWithContentType(body, headers, "text/plain")
_, _ = identity, findings
```

`Snapshot` 可以复制、并发使用；其规则与 AC 索引来自同一发布代次。后续 `AddRule` 不改变已有快照，需要再次调用 `extractor.Snapshot()` 才能观察更新。正文、响应头及规则入参的所有权约束不变。

`Identity()` 是进程内缓存身份，不是规则内容摘要、可持久化版本号或跨进程标识。不同提取器实例（包括空的零值实例）及每次成功的 `AddRule` 发布均获得不同的非零身份；相同实例未更新时身份稳定，失败的 `AddRule` 不改变身份。显式零值 `Snapshot` 是身份为 0 的空规则集。即使再次提交相同规则，成功发布也会产生新身份。

## 通过既有 Information 插件使用

`passive/plugins.Information` 复用同一提取器，并分别记录检查过的正文和响应头。重复输入跳过对应的提取，旧发现只报告一次。每次分析固定使用一个规则快照，成功 `AddRule` 后的新分析按新规则检查，已开始的分析可按旧快照完成。

```go
registry, err := passive.New([]passive.Plugin{
    &plugins.Information{Extractor: infoextract.New()},
}, 128)
```

以上片段还需导入 `github.com/emhha/netloom/passive` 与 `github.com/emhha/netloom/passive/plugins`。Registry 不强制所有插件使用 AC；这是提取器和各插件选择共享引擎的实现决策。插件的输入要求、缓存和其他内置分析器见 [内置被动插件](../passive/plugins/README.md)，跨包契约见 [API 与配置](../docs/API.md#扩展契约)。
