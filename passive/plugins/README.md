# 内置被动分析插件

`github.com/emhha/netloom/passive/plugins` 提供实现 `passive.Plugin` 的离线分析器。插件只读取调用方交付的 HTTP 快照，不补抓证据、不持久化结果。Registry、输入所有权和扩展契约见 [API 与配置](../../docs/API.md#扩展契约)；包说明见 [doc.go](doc.go)。

## 显式选择插件

使用 `passive.New` 注册需要的插件；导入包不会自动注册或运行分析。Registry 只负责插件调度与缓存，不强制所有插件使用 AC，也不对所有插件统一执行 AC 预筛选。是否使用公共 [ac 引擎](../../ac/README.md) 由各插件自行选择。

信息提取插件通过 `passive/plugins/infoextract.New()` 构造。规则、AC 匹配和去重都在该插件包中实现，见 [信息提取插件说明](infoextract/README.md)。

| 插件 | 注册 ID | 用途 |
| --- | --- | --- |
| `infoextract.Plugin` | `infoextract` | 提取敏感信息候选，独立去重正文与响应头 |
| `Fingerprint` | `fingerprint` | 使用调用方提供的 `Engine` 匹配已取得的请求/响应技术指纹 |
| [`serialization.Plugin`](serialization/README.md) | `serialization` | 有界识别序列化格式及协议线索，不执行反序列化 |

## 缓存策略

`infoextract` 由插件内部判断正文和响应头是否已检查，命中时跳过并且不重发旧发现。`Fingerprint` 以请求及响应证据（包括头、正文和状态码等）为键。使用 `passive.New` 时，命中就复用指纹结果。`serialization.Plugin` 的 `CacheKey` 为空，每次执行自己的有界检查。自定义插件通过 `CacheKey` 决定哪些输入可以复用。调用方可以选用 `passive.NewDeduplicating`，让有键的插件命中后只报告 `CacheHit`，不保留或重发旧的 `Artifacts` 或 `Data`。
