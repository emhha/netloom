# 序列化格式线索插件

`github.com/emhha/netloom/passive/plugins/serialization` 提供序列化格式线索插件。使用 `serialization.New()` 构造，`serialization.Plugin{}` 零值也可用。注册 ID 为 `serialization`，版本为 `"1"`。插件仅检查已有 HTTP 快照。

## 调用示例

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
    "github.com/emhha/netloom/passive/plugins/serialization"
)

func main() {
    registry, err := passive.New([]passive.Plugin{
        serialization.New(),
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
            Findings []serialization.Finding `json:"findings"`
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

Registry 要求 `Input.Request` 和 `Input.Response` 均非 nil；没有实际响应正文时可以像示例一样提供空的响应快照。输入在分析期间应保持只读。`ids=nil` 会运行该 Registry 已注册的全部插件，不代表自动加载全部内置插件。缓存容量由 `passive.New` 显式选择，0 使用 Registry 默认值 128；`Plugin.CacheKey` 返回空字符串，禁用该插件的结果缓存，不为复用额外保留捕获凭据。

## 扫描范围与有界解码

- 观察请求 URL、请求头、请求正文，以及响应头、响应正文。
- 对 URL 查询参数值和已声明 `application/x-www-form-urlencoded` 的请求正文参数值，最多做一层 URL/form 解码（`+` 表示空格）；Cookie 和其他正文的百分号解码保留 `+`。对标准及 URL-safe Base64 最多做一层有界解码并校验 padding。编码只是观察路径，不是序列化格式或风险证明，不递归展开任意嵌套编码。
- 识别二进制 magic、文本格式特征、响应中的反序列化错误串，以及协议位置的弱线索。规则匹配不实例化类型、不调用对象构造或反序列化器。
- 每个 `passive.Input` 的固定总扫描预算为 **1 MiB**，最多 **128 个观察面**，最多 **64 个 findings**；不是每个头字段或每种解码各有一份预算。原始观察和有界解码受同一次分析预算约束。
- 超过扫描字节、观察面或 findings 上限时，`Result.Truncated=true`；输入已有 `Response.BodyTruncated=true` 时也传播该标记。头名称也计入字节预算，空头值和空参数消耗观察面预算；单侧头字段名超过 128 个时跳过该侧头部，单字段值超过 128 项时只保留前 128 项，以约束预处理成本。截断仍可保留已经取得的 findings，不能把未命中解释为完整排除。

输入模型仅为 `httpdata` 的 HTTP 快照，不解析原始 TCP、Redis 或 MQ 流，也不依据端口判断协议。插件只消费已捕获字节：不解压、不解密，不跟随 URL、不发起 DNS/HTTP 或其他网络请求，不跨请求、会话或流关联。压缩内容若未由调用方预先解压、加密 Cookie、深层嵌套编码及预算外内容均可能没有可识别特征。

## 规则候选与共享 AC

文本规则使用公共 `ac.Matcher`（固定版本 Cloudflare 的线程安全薄适配）扫描必要触发词，只依赖唯一命中词集合，不依赖回调顺序或出现次数，再按既有规则顺序评估候选；仅候选需要执行对应正则。可证明与原规则等价的安全固定字面量规则可直接命中，不再重复执行正则。不能安全提取必要触发词的规则保留完整正则 fallback，不能为了预筛选而排除原本可匹配的输入。

尤其是大小写不敏感的 `rememberMe` 规则，仍用正则 fallback，而不只枚举 ASCII 大小写触发词；Go 正则的 Unicode 大小写折叠可能匹配 ASCII 枚举之外的字符，预筛选不能因此漏报。二进制 magic 仍使用前缀检查，不因字节串出现在内容中间而直接命中。

共享 AC 仅改变文本候选筛选实现；URL/form 与 Base64 观察流程、1 MiB/128/64 总预算、finding 顺序、去重及以下输出/证据语义保持不变。它不增加解码层数，也不将弱线索提升为漏洞结论。

## 结果与证据语义

`Finding` 是公开的 finding 类型，可用于解码 `Result.Data` 中的 `findings` 数组。`Result.Data` 是 JSON；例如，上述请求正文的 magic 对应的 finding 如下（其他载体还可能产生附加线索）：

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

## 避免误判

- JSON 的 `@type`、`@class`、`$type` 可用于正常业务数据或文档，单独出现不构成强结论，更不能证明任意类型实例化。
- `rememberMe` 只是常见 Cookie/字段名，不能据此确认框架、加密算法、密钥问题或反序列化漏洞。
- 普通 Base64 内容本身不是序列化证据；解码后仍需匹配格式特征。端口、路径及协议位置只能提供弱线索，不证明该协议正在运行。
- 响应中的格式内容可能是文档、示例或请求回显；响应内容特征会降低强度，避免将它等同于真实的请求序列化输入。不得因为响应引用了二进制 magic 或示例文本，就断言服务端消费了该格式。
- 反序列化错误串只是**响应线索**，可能来自日志、静态文档、代理或上游系统；不证明当前请求触发了反序列化，也不证明可利用性。不以单独出现的 `ModuleNotFoundError`、`ClassNotFoundException` 等通用依赖错误推断序列化格式。
- 即使请求出现明确 magic，`strong` 也只代表字节特征更明确；不能证明数据结构有效、服务端接受了它、存在危险 gadget 或可远程执行代码。无 finding 同样不等于没有序列化或没有漏洞。

插件不提供主动探测、漏洞确认、payload 构造、gadget 分析、解密或跨流攻击链推断。进一步验证必须由调用方在明确授权与隔离环境中自行决定。
