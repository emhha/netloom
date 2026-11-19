# 内置被动分析插件

`github.com/emhha/netloom/passive/plugins` 提供实现 `passive.Plugin` 的离线分析器。插件只读取调用方交付的 HTTP 快照，不补抓证据、不持久化结果。Registry、输入所有权和扩展契约见 [API 与配置](../../docs/API.md#扩展契约)；包说明见 [doc.go](doc.go)。

## 显式选择插件

使用 `passive.New` 注册需要的插件；导入包不会自动注册或运行分析。Registry 只负责插件调度与缓存，不强制所有插件使用 AC，也不对所有插件统一执行 AC 预筛选。是否使用公共 [ac 引擎](../../ac/README.md) 由各插件自行选择。

`Information` 继续使用调用方提供的 `infoextract.InfoExtractor`；该提取器内部复用公共 AC，不依赖 Registry 才能工作。独立提取与规则扩展见 [infoextract 说明](../../infoextract/README.md)。

| 插件 | 注册 ID | 用途 |
| --- | --- | --- |
| `Information` | `infoextract` | 用 `Extractor` 提取敏感信息候选，正文与响应头分别缓存 |
| `Fingerprint` | `fingerprint` | 使用调用方提供的 `Engine` 匹配已取得的请求/响应技术指纹 |
| `Serialization` | `serialization` | 有界识别序列化格式及协议线索，不执行反序列化 |

`Serialization` 零值可用，不需要规则文件、客户端或初始化资源；元数据版本为字符串 `"1"`。不要据此推断其他插件也无需配置依赖。

## Information：规则更新与缓存

`Information` 必须配置非 nil 的 `Extractor`；缺失时分析返回错误。插件元数据版本为字符串 `"5"`。`CacheKey` 为空，外层 Registry 每次调用它。插件内部对正文与响应头分别去重，`CacheLimit=0` 使用合计 256 条的默认容量，负数禁用去重。缓存只记完成标记。命中时跳过对应部分的提取，`body_cache_hit` 或 `header_cache_hit` 为 true，该部分不会再次报告旧发现。

正文默认按项目、会话、规范化 URL、媒体类型和长度去重，无需散列正文。完整响应使用实际交给插件的正文长度。截断的正文使用有效的 `Content-Length`、已采集长度和内容编码，和完整响应分别去重。截断且无法确定长度时继续分析。等长内容更新可能被略过。需要区分等长变化时，显式设置 `HashBodyForCache: true`，按采集字节计算哈希。响应头使用独立的缓存键，变化的头仍会检查。

每次 `Analyze` 捕获同一份不可变 `infoextract.Snapshot`，同时用于正文、响应头的规则匹配。成功的 `AddRule`（新增、替换或重复提交同名规则）、切换提取器实例或更改正文去重模式，都会清除先前的完成标记；失败的规则更新保留标记。

与更新重叠的在途调用允许按旧快照完成，结束后其旧 Registry 即可回收。`Information` 支持并发分析和提取器的并发 `AddRule`。在使用前设置公开配置字段，分析期间保持配置不变。

## 其他插件

`Fingerprint` 以请求及响应证据（包括头、正文和状态码等）为键。使用 `passive.New` 时，命中就复用指纹结果。`Serialization` 的 `CacheKey` 为空，每次执行自己的有界检查。自定义插件通过 `CacheKey` 决定哪些输入可以复用。调用方可以选用 `passive.NewDeduplicating`，让有键的插件命中后只报告 `CacheHit`，不保留或重发旧的 `Artifacts` 或 `Data`。

## Serialization：离线格式线索

### 调用示例

以下示例只分析内存中的合成快照，不创建网络 Engine，也不向示例 URL 发送请求：

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/emhha/netloom/httpdata"
    "github.com/emhha/netloom/passive"
    "github.com/emhha/netloom/passive/plugins"
)

func main() {
    registry, err := passive.New([]passive.Plugin{
        &plugins.Serialization{}, // 零值可用；显式 opt-in
    }, 128)
    if err != nil {
        panic(err)
    }
    input := passive.Input{
        Request: &httpdata.Request{
            URL: "https://service.example/api",
            Method: http.MethodPost,
            Header: http.Header{"Content-Type": {"application/octet-stream"}},
            // Java 序列化流 magic；不是可执行对象或漏洞验证载荷。
            Body: []byte{0xac, 0xed, 0x00, 0x05},
        },
        Response: &httpdata.Response{
            StatusCode: http.StatusNoContent,
            Header: http.Header{},
        },
    }
    results, err := registry.Analyze(context.Background(), input, []string{"serialization"})
    if err != nil {
        panic(err)
    }
    for _, result := range results {
        if result.Status != "completed" {
            fmt.Println("analysis failed:", result.Error)
            continue
        }
        var data struct {
            Findings []plugins.SerializationFinding `json:"findings"`
            PassiveOnly bool `json:"passive_only"`
        }
        if err := json.Unmarshal(result.Data, &data); err != nil {
            panic(err)
        }
        fmt.Printf("passive_only=%t truncated=%t findings=%d\n",
            data.PassiveOnly, result.Truncated, len(data.Findings))
        for _, finding := range data.Findings {
            fmt.Println(finding.Format, finding.Strength, finding.Scope)
        }
    }
}
```

Registry 要求 `Input.Request` 和 `Input.Response` 均非 nil；没有实际响应正文时可以像示例一样提供空的响应快照。输入在分析期间应保持只读。`ids=nil` 会运行该 Registry 已注册的全部插件，不代表自动加载全部内置插件。缓存容量由 `passive.New` 显式选择，0 使用 Registry 默认值 128；`Serialization.CacheKey` 返回空字符串，禁用该插件的结果缓存，不为复用额外保留捕获凭据。

### 扫描范围与有界解码

- 观察请求 URL、请求头、请求正文，以及响应头、响应正文。
- 对 URL 查询参数值和已声明 `application/x-www-form-urlencoded` 的请求正文参数值，最多做一层 URL/form 解码（`+` 表示空格）；Cookie 和其他正文的百分号解码保留 `+`。对标准及 URL-safe Base64 最多做一层有界解码并校验 padding。编码只是观察路径，不是序列化格式或风险证明，不递归展开任意嵌套编码。
- 识别二进制 magic、文本格式特征、响应中的反序列化错误串，以及协议位置的弱线索。规则匹配不实例化类型、不调用对象构造或反序列化器。
- 每个 `passive.Input` 的固定总扫描预算为 **1 MiB**，最多 **128 个观察面**，最多 **64 个 findings**；不是每个头字段或每种解码各有一份预算。原始观察和有界解码受同一次分析预算约束。
- 超过扫描字节、观察面或 findings 上限时，`Result.Truncated=true`；输入已有 `Response.BodyTruncated=true` 时也传播该标记。头名称也计入字节预算，空头值和空参数消耗观察面预算；单侧头字段名超过 128 个时跳过该侧头部，单字段值超过 128 项时只保留前 128 项，以约束预处理成本。截断仍可保留已经取得的 findings，不能把未命中解释为完整排除。

输入模型仅为 `httpdata` 的 HTTP 快照，不解析原始 TCP、Redis 或 MQ 流，也不依据端口判断协议。插件只消费已捕获字节：不解压、不解密，不跟随 URL、不发起 DNS/HTTP 或其他网络请求，不跨请求、会话或流关联。压缩内容若未由调用方预先解压、加密 Cookie、深层嵌套编码及预算外内容均可能没有可识别特征。

### 规则候选与共享 AC

文本规则使用公共 `ac.Matcher`（固定版本 Cloudflare 的线程安全薄适配）扫描必要触发词，只依赖唯一命中词集合，不依赖回调顺序或出现次数，再按既有规则顺序评估候选；仅候选需要执行对应正则。可证明与原规则等价的安全固定字面量规则可直接命中，不再重复执行正则。不能安全提取必要触发词的规则保留完整正则 fallback，不能为了预筛选而排除原本可匹配的输入。

尤其是大小写不敏感的 `rememberMe` 规则，仍用正则 fallback，而不只枚举 ASCII 大小写触发词；Go 正则的 Unicode 大小写折叠可能匹配 ASCII 枚举之外的字符，预筛选不能因此漏报。二进制 magic 仍使用前缀检查，不因字节串出现在内容中间而直接命中。

共享 AC 仅改变文本候选筛选实现；URL/form 与 Base64 观察流程、1 MiB/128/64 总预算、finding 顺序、去重及以下输出/证据语义保持不变。它不增加解码层数，也不将弱线索提升为漏洞结论。

### 结果与证据语义

`SerializationFinding` 是公开的 finding 类型，可用于解码 `Result.Data` 中的 `findings` 数组。`Result.Data` 是 JSON；例如，上述请求正文的 magic 对应的 finding 如下（其他载体还可能产生附加线索）：

```json
{
  "findings": [
    {
      "format": "java-object-stream",
      "rule": "magic.java",
      "strength": "strong",
      "scope": "request.body",
      "encoding": "raw",
      "evidence": "magic.java"
    }
  ],
  "passive_only": true
}
```

| 字段 | 含义与边界 |
| --- | --- |
| `format` | 规则提示的格式名，不是确认存在的服务端反序列化器 |
| `rule` | 命中的规则标识，用于解释及分组 |
| `strength` | `strong` / `medium` / `weak`，**只表示格式特征强度，不是漏洞严重度、利用概率或漏洞结论** |
| `scope` | 观察位置，用于区分请求/响应及相应载体 |
| `encoding` | 命中所在的原始或解码观察路径，不表示进行过反序列化 |
| `evidence` | 有界特征片段；使用固定规则标签表达特征，避免回显原始敏感值，不是完整 payload 或原文摘录 |
| `passive_only` | 固定为 `true`，表明结果来自被动分析 |

`Result.Artifacts` 提供便于汇总的对应条目：`Type="serialization_hint"`，`Rule` 对应命中规则，`Scope` 为观察位置，`Value` 仅包含格式名及强度，不携带原始 Cookie、令牌、正文或其他敏感值。不要把 Artifact 当作原始流量存档；确需保留授权证据时由调用方另行控制访问、脱敏和生命周期。

### 避免误判

- JSON 的 `@type`、`@class`、`$type` 可用于正常业务数据或文档，单独出现不构成强结论，更不能证明任意类型实例化。
- `rememberMe` 只是常见 Cookie/字段名，不能据此确认框架、加密算法、密钥问题或反序列化漏洞。
- 普通 Base64 内容本身不是序列化证据；解码后仍需匹配格式特征。端口、路径及协议位置只能提供弱线索，不证明该协议正在运行。
- 响应中的格式内容可能是文档、示例或请求回显；响应内容特征会降低强度，避免将它等同于真实的请求序列化输入。不得因为响应引用了二进制 magic 或示例文本，就断言服务端消费了该格式。
- 反序列化错误串只是**响应线索**，可能来自日志、静态文档、代理或上游系统；不证明当前请求触发了反序列化，也不证明可利用性。不以单独出现的 `ModuleNotFoundError`、`ClassNotFoundException` 等通用依赖错误推断序列化格式。
- 即使请求出现明确 magic，`strong` 也只代表字节特征更明确；不能证明数据结构有效、服务端接受了它、存在危险 gadget 或可远程执行代码。无 finding 同样不等于没有序列化或没有漏洞。

插件不提供主动探测、漏洞确认、payload 构造、gadget 分析、解密或跨流攻击链推断。进一步验证必须由调用方在明确授权与隔离环境中自行决定。
