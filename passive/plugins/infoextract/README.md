# 信息提取插件

`github.com/emhha/netloom/passive/plugins/infoextract` 提供 `passive.Plugin`，注册 ID 为 `infoextract`，版本为 `"5"`。插件在调用方提供的 HTTP 响应中查找敏感信息候选。它可与主动请求或 MITM 共用，也可交给 Registry 分析已有快照。

## 注册和扩展规则

```go
import (
    "github.com/emhha/netloom/passive"
    "github.com/emhha/netloom/passive/plugins/infoextract"
)

plugin := infoextract.New()
err := plugin.AddRule(infoextract.Rule{
    Name: "example_marker", Pattern: "example_marker=[a-z]+",
    Scope: "body", Triggers: []string{"example_marker="},
})
if err != nil {
    return err
}
registry, err := passive.New([]passive.Plugin{plugin}, 128)
```

`New` 加载内置凭据类规则。若只需调用方自己的规则，可用零值 `&infoextract.Plugin{}`。通过 `AddRule` 新增或替换同名规则，失败时保留现有规则。触发词切片会被复制，规则更新可以和分析并发执行。同一次分析的正文和响应头使用同一个规则快照。

规则支持 `Scope` 为 `body`、`header` 或 `all`，省略时为 `all`。触发词命中后运行对应正则，无触发词的规则直接运行。仅含空字符串的非空触发词列表不会命中。标为 `special` 的规则在正文中只检查 JS 和 JSON。二进制类型不检查正文，仍可以检查响应头。JS 正文只检查前 100 KiB。

分析结果通过 `passive.Result.Artifacts` 返回，类型为 `sensitive_candidate`。`Rule` 为规则名，`Scope` 为命中位置，`Value` 为完整匹配。发现可能包含敏感值，调用方负责处理这些结果。

## 去重

默认按项目、会话、规范化 URL、媒体类型和正文长度判断正文是否检查过。截断时使用有效的 `Content-Length`、已采集长度和内容编码；长度未知时继续分析。等长更新可能被跳过。设置 `HashBodyForCache: true` 可按采集正文的哈希区分等长变化。

响应头独立去重。命中会跳过相应检查并设置 `body_cache_hit` 或 `header_cache_hit`，不再报告此前的发现。正文和头部合用 `CacheLimit`，零值为 256，负值禁用去重。成功更新规则会清除完成标记。在开始分析前设置插件配置字段。

关于接入网络流量，见 [traffic](../../../traffic/README.md)。其它内置插件见 [被动插件](../README.md)。
