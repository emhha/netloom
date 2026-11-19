# Serialization 共享 AC 性能

日期：2026-11-10。工具链 Go 1.26.3 linux/amd64，AMD Ryzen 7 6800H 虚拟化环境，`-cpu=4`。这是离线合成 HTTP 快照的本机基准，不是实际流量、网络延迟或漏洞验证。

## 实现与比较边界

- 新实现使用固定版本 Cloudflare ahocorasick，经公共 [ac 薄适配](../ac/README.md) 返回唯一命中词。规则候选使用 bitset、按原规则顺序输出；有限的安全字面量直接匹配，其余候选继续正则复核，无安全触发词的规则始终运行正则。
- 基线为测试中的[冻结线性实现](../passive/plugins/serialization/serialization_linear_test.go)，保留原始逐规则正则及相同的解码、预算和输出逻辑，不为衬托新实现而修改基线算法。[冻结表断言及全管线对照](../passive/plugins/serialization/serialization_equivalence_test.go) 检查 regex、属性、magic、预算和完整 Result；性能测量前全仓测试及 race 已通过。
- 此处衡量的是“候选筛选＋安全字面量替代”的整体变化，**不能全部归因为 Cloudflare 库本身**。不同第三方 AC 内核的同口径比较见 [AC 选型](AC-SELECTION.md)。fingerprint 内核未改。
- 构造 matcher、初始化全局规则和构造输入不计入每次扫描计时。完整插件基准直接调用 `Analyze`，包含路由、预处理、解码、去重、JSON 和 Artifacts 生成；不经过 Registry 缓存，也不包含输入抓取、网络或 matcher 构建。
- 基准串行调用，`-cpu=4` 只设置 GOMAXPROCS；下表是每次调用耗时，不是四路并发摊销时间。性能测量与全仓 race/fuzz 分开运行。

## 完整插件：主要结果

每项 `-benchtime=1s -count=3`，取三次中位数。时间单位 ms/op；倍数为线性耗时除以新耗时。B/op 与 allocs/op 也各自取中位数，不将累计分配当作保留堆或峰值 RSS。

| 合成场景 | 线性 ms/op | AC ms/op | 倍数 | B/op：线性 → AC | allocs/op：线性 → AC |
| --- | ---: | ---: | ---: | ---: | ---: |
| 64 KiB 普通无命中请求体 | 32.303 | 2.271 | 14.22× | 14,750 → 11,402 | 239 → 240 |
| 64 KiB 高频触发/复杂正则请求体 | 30.139 | 20.423 | 1.48× | 15,544 → 16,142 | 208 → 211 |
| JSON 响应，固定片段×1100 | 43.770 | 5.018 | 8.72× | 11,050 → 11,232 | 217 → 218 |
| form 请求，8 个 Base64 参数 | 0.177 | 0.037 | 4.79× | 6,232 → 6,141 | 112 → 113 |
| 60,004 B 二进制响应，含 Java magic | 46.343 | 3.794 | 12.21× | 11,207 → 1,142 | 16 → 16 |

原始输出：[完整插件 1s×3](benchmarks/serialization/benchmark-pipeline-1s.txt)。JSON/form/二进制基准在进入计时前检查新旧完整输出一致。

主要收益在少量候选或无候选时避免大部分逐条正则扫描。高频触发输入仍须运行复杂正则，收益明显较小；该输入不是“全规则均成功命中”，而是大量候选及部分正则命中。新实现**并不保证更少分配**：如表中若干场景增加 1–3 次分配，密集场景累计分配字节也略增。不得宣称零分配或所有输入都同等加速。

## 分层补充：文本匹配与完整分析

[分层基准源码](../passive/plugins/serialization/serialization_match_test.go) 另以 `100ms×3` 测量文本匹配和完整 `Analyze`。下面仅用于说明各层差异，不与上表混用样本；短采样中慢场景每次只有少量迭代，时序及正则内部池造成的分配波动较大。

| 场景 | 文本线性 → AC ms/op | 完整分析线性 → AC ms/op |
| --- | ---: | ---: |
| 4 KiB 无命中 | 2.912 → 0.136 | 2.113 → 0.238 |
| 64 KiB 无命中 | 46.079 → 2.188 | 38.392 → 2.351 |
| 256 KiB 无命中 | 189.160 → 9.112 | 141.571 → 9.516 |
| 64 KiB 混合线索 | 45.994 → 20.529 | 29.305 → 19.154 |
| 64 KiB 高频触发 | 41.294 → 20.428 | 28.953 → 21.061 |
| encoded-fields | 0.680 → 0.032 | 0.726 → 0.113 |

文本基准复核请求及响应全部文本规则；完整分析按请求/响应路由选择规则，并带有其余处理成本，因此两列不是可直接相减的相同工作量。`encoded-fields` 是含编码字段的普通请求体，没有 form Content-Type；真实 form 解析收益应以上表的 `form-base64` 为准。

原始输出：[分层 100ms×3](benchmarks/serialization/benchmark-cloudflare.txt)；全部逐项中位数：[JSON 数据](benchmarks/serialization/medians.json)。

## 内存与适用范围

- Cloudflare 自动机使用稠密指针表，匹配返回命中 ID 切片，并使用原子计数和 `sync.Pool`。它不是零分配、零共享状态的实现；只允许通过上游线程安全入口共享扫描。
- [选型时的保留堆实验](AC-SELECTION.md) 中，两份独立的小词表自动机构建后近似保留堆合计约 4.08 MiB，明显高于 Bobu 新版约 0.89 MiB。该数值来自隔离词表实验，不是本次整个插件进程的内存实测；这里没有测量峰值 RSS。
- 不将本表推广到大型指纹字典、任意正则、高熵流量或不同 Go/CPU。大量 fallback 或所有候选都命中时，收益可能进一步缩小；当前吞吐优先选型在词表或内存预算变化后应重测。
- infoextract 已通过兼容性、所有权与并发回归，本记录没有测量其完整提取流水线的新旧收益；选型报告的 Information 词表扫描仅是库级结果。

## 复现

```sh
go test ./passive/plugins/serialization -run '^$' -bench 'BenchmarkSerialization(Text|Analyze|Pipeline)$' -benchmem -benchtime=100ms -count=3 -cpu=4
go test ./passive/plugins/serialization -run '^$' -bench 'BenchmarkSerialization(Analyze|Pipeline)/(64KiB-nohit|64KiB-dense|json-response|form-base64|binary-response)' -benchmem -benchtime=1s -count=3 -cpu=4
```

输入生成器、固定 witness 和冻结实现均位于测试源码，不需要下载远程流量。原始输出、中位数及相关源码校验值见 [SHA256SUMS](benchmarks/serialization/SHA256SUMS)；正确性及执行范围见 [验证记录](VALIDATION.md)。
