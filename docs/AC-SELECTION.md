# AC 库选型：信息提取与序列化候选筛选

选型日期：2026-11-10。本报告保留选型阶段的独立库级测量，不把其结果当作端到端收益。后续共享 [ac 适配层](../ac/README.md) 已按本结论接入固定版本 Cloudflare；接入后的测试及插件级性能另见 [验证记录](VALIDATION.md) 和 [Serialization 性能记录](PERFORMANCE-serialization.md)。

## 结论

当前内置小型词表、吞吐优先的条件下，推荐 **`github.com/cloudflare/ahocorasick`**，固定版本 `v0.0.0-20240916140611-054963ec9396`，只使用共享实例的 `MatchThreadSafe`，外层做薄适配。

- 它直接处理 `[]byte`，返回每次扫描命中的唯一关键词下标，符合“关键词 → 规则候选 → 正则复核”的需求。
- 在本次 HTML 无命中/稀疏命中、JSON、二进制及 4-way 并发样本中，比另外两个字节型候选更快；不依据品牌或上游宣传跑分作选择。
- 代价是自动机内存明显较大，命中结果切片仍有分配。当前两份小型词表的构建后保留堆合计约 **4.08 MiB**，与 Bobu 新版约 **0.89 MiB** 相比更大。
- **Bobu 新版 `Walk` 是内存/分配优先时的备选**，且本次高频重复命中更快。若词表显著扩张，或内存预算不接受约 4 MiB，应重新评估，不能把本结论推广到大规模指纹规则集。
- 不继续维护新写的 AC 算法内核，也不为两个插件引入多后端选择框架。本次不建议更换既有 fingerprint 内核。

## 需求与统一比较口径

需求是完整的**命中关键词集合**，不是位置、出现次数、仅首个命中或仅最长命中：

- 精确字节匹配，大小写敏感，支持 NUL、`0xff` 和非法 UTF-8。
- 同时保留重叠及失败链后缀匹配，例如 `she` 与 `he`。
- 关键词先去空串、去重复，再建立唯一关键词 ID 到一或多个业务规则的映射。
- 自动机构建后共享；每次扫描的候选状态独立，不依赖输出顺序。
- 无安全触发词的正则仍走 fallback；第三方 AC 不负责证明触发词提取与正则等价。

对照中所有实现写入相同的调用方 `[]bool` 集合，集合预分配、逐次清空。Cloudflare 用 `MatchThreadSafe`，Bobu 用 `Walk`，petar 用 `StandardMatch + IterOverlappingByte`，分别测 NFA/DFA。`bytes.Contains` 为逐词基线，当前轮预先转换关键词，不把 string→byte 分配算入每次扫描。没有用 `Contains` 提前返回替代全部命中，也没有用 `LeftMostLongest` 偷换语义。

## 候选与适配取舍

| 候选 | 优点 | 风险/成本 | 判断 |
| --- | --- | --- | --- |
| Cloudflare | 原始字节、唯一关键词下标、完整重叠/后缀；本次多数场景最快 | `Match` 不并发安全；TS 有原子计数器和池化 map；密集指针表占内存；命中切片分配 | 当前吞吐优先首选 |
| Bobu 新版 | 字节 `Walk` 回调；构建后扫描只读；本次扫描 0 B/op；比 Cloudflare 省堆 | 仍逐 occurrence 回调；密集转移表不适合无界大词表；新版构建较慢，未发新稳定标签 | 内存/分配优先备选 |
| petar NFA/DFA | 字节 API；本次 NFA 保留堆最小 | 必须 Standard + overlapping；迭代器/每次匹配对象产生分配；本次实际扫描明显较慢 | 当前不选 |
| anknown | double-array trie；MIT | API 是 `[][]rune` / `[]rune`，无直接关键词 ID；常规 UTF-8 解码会合并不同非法字节；人为逐字节映射又引入转换和映射成本 | 本用途静态筛除，未计时 |

Cloudflare 和 Bobu 对重复字节关键词都可能只保留一个终端 ID；不得将每条规则的 trigger 不加去重地平铺后直接当规则 ID 使用。

## 实测

环境：Go 1.26.3 linux/amd64，AMD Ryzen 7 6800H（虚拟机可见 CPU），`-cpu=4`，每个基准 `100ms × 3`，下表为三次中位数。不是统计显著性检验，也不代表真实流量分布。

词表从当前规则提取并冻结在基准源码：Information 26 个唯一关键词 / 200 字节；Serialization 57 个 / 819 字节。语料为合成 HTML、JSON、固定种子随机二进制、末尾三个稀疏命中及三个词高频重复。没有保存真实流量或凭据。

### Serialization：每次扫描 64 KiB，微秒/次，越小越好

| 输入 | Cloudflare TS | Bobu 新版 Walk | petar NFA | petar DFA | 逐词 Contains |
| --- | ---: | ---: | ---: | ---: | ---: |
| HTML 无命中 | **128.86** | 153.31 | 833.18 | 358.81 | 824.17 |
| HTML 稀疏命中 | **131.79** | 154.17 | 852.68 | 359.07 | 922.55 |
| JSON | **97.20** | 166.44 | 823.50 | 490.35 | 320.75 |
| 随机二进制 | **131.59** | 165.33 | 806.06 | 385.71 | 302.51 |
| 高频重复命中 | 234.32 | **199.43** | 985.61 | 1118.65 | 555.08 |

JSON/二进制不标为“无命中”：Serialization 的 `[` 等触发词确实可能出现。词命中不等于最终正则或 finding 命中。

### 共享实例并发：64 KiB 稀疏命中

`RunParallel`，4-way；这里的 ns/op 是总吞吐摊销，不是单请求延迟。

| 词表 | Cloudflare TS | Bobu 新版 | petar NFA | petar DFA |
| --- | ---: | ---: | ---: | ---: |
| Information | **30.68 µs** | 39.37 µs | 204.91 µs | 113.50 µs |
| Serialization | **34.58 µs** | 40.06 µs | 216.93 µs | 114.47 µs |

### 内存、分配和构建

| 指标（Serialization 词表） | Cloudflare TS | Bobu 新版 | petar NFA | petar DFA |
| --- | ---: | ---: | ---: | ---: |
| 构建后保留 Go 堆，约 | 3.27 MiB | 0.72 MiB | 0.13 MiB | 0.47 MiB |
| 一次构建耗时，中位数 | 2.26 ms | 11.13 ms | 0.33 ms | 9.09 ms |
| 一次构建累计分配，约 | 3.31 MiB | 1.62 MiB | 0.25 MiB | 3.57 MiB |
| 稀疏命中，B/op / allocs/op | 24 / 1 | 0 / 0 | 200 / 5 | 264 / 13 |
| 高频重复命中，B/op / allocs/op | 24 / 1 | 0 / 0 | 143096 / 5959 | 238427 / 17875 |

“保留 Go 堆”是显式 GC 后 `HeapAlloc` 差值，受分配器/运行时噪声影响，**不是峰值 RSS**。构建累计分配也不是峰值。低到千字节以下的差值不宜解释为精确内存大小。Cloudflare 热池无命中在本次基准为 0 B/op，但冷池、GC 丢池及并发扩张仍可能分配 map，不能宣称永远零分配。

### Bobu 版本不能混为一谈

- 最新稳定标签 `v1.0.3`（2020）使用 `int64` callback 和转移表，带运行期 failure 跳转。
- 本次主要对比的新版固定为 `v1.0.4-0.20250611112625-b4b5728e36fc`（2025），使用 `uint32` callback/表和预计算转移。
- 稳定版也通过同一组随机字节/并发正确性对照；它的 Serialization 保留堆约 1.44 MiB，新版约 0.72 MiB。单独保留[稳定版 Bobu 跑分](benchmarks/ac-selection/benchmark-bobu-v1.0.3.txt)，不将新版 API/内存结论冒充稳定标签的行为。

## 正确性与验证边界

已通过：

1. 120 组固定种子字典/任意字节输入，以逐关键词 `bytes.Contains` 为 oracle；包括重叠、后缀、大小写、空/重复词正规化、非法 UTF-8 和 NUL。
2. 8 个 goroutine 共享构建完成的 matcher，各自独立候选集合，重复 100 次；运行 race detector。
3. 两份冻结词表在 JSON/二进制语料上再次集合等价和 race 检查。
4. 普通/并发/构建基准正常结束；主模块依赖文件没有变更。

限制：此次是库级选型，不是完整插件验收。没有实测峰值 RSS、百万词字典、长期 fuzz、完整 AC→regex→解码流程收益或真实生产流量。没有因此将此前版本的全仓检查结果认作当前重构通过；接入内核后仍须跑插件等价性、端到端基准和全仓检查。

## 建议接入方式

1. 共用薄适配层：去空词、去重、保存关键词下标映射；不在外层重写 trie/failure 算法。
2. 初始化完成后安全发布 `*Matcher`；所有共享扫描统一使用 Cloudflare `MatchThreadSafe`，不可与非线程安全的 `Match` 混用，也不通过全局互斥锁串行化所有请求。
3. Serialization 将命中关键词映射为规则 bitset，按原规则顺序复核候选正则；Information 保持已有 AC→regex 行为与插件入口。
4. API 只承诺业务需要的候选集合，不为适配第三方额外承诺 occurrence 顺序或回调次数。
5. 不需要把 Information 引擎迁入 passive，也不需要重写 Registry 或 fingerprint。

以上为选型时提出的迁移方案，后续已在共享适配层及两个调用方落实；原始选型输出保持不变，接入验证和端到端基准单独记录。

## 复现与证据

为了不向 SDK 引入第二个 module，评测源与依赖清单以文本附件归档。在**仓库外的独立目录**中，将 [依赖清单](benchmarks/ac-selection/go.mod.txt)、[校验清单](benchmarks/ac-selection/go.sum.txt)、[主基准源码](benchmarks/ac-selection/evaluation_test.go.txt)、[补充语料源码](benchmarks/ac-selection/varied_test.go.txt) 去掉 `.txt` 后缀，再执行：

```sh
go test -race -v ./...
go test -run '^TestRetainedHeap$' -v -count=1 -cpu=4
go test -run '^$' -bench 'BenchmarkScan|BenchmarkParallelScan|BenchmarkBuild' -benchmem -benchtime=100ms -count=3 -cpu=4
go test -run '^$' -bench '^BenchmarkVaried$' -benchmem -benchtime=100ms -count=3 -cpu=4
```

全部词表与生成语料内嵌，依赖只需常规 Go module 下载；不依赖开发机路径。清单保留静态研究时下载的 anknown/darts 固定版本，但基准代码不导入它们。

- [普通/并发/构建原始输出](benchmarks/ac-selection/benchmark-current.txt)
- [JSON/二进制原始输出](benchmarks/ac-selection/benchmark-varied.txt)
- [非 race 保留堆样本](benchmarks/ac-selection/memory-current.txt)
- [主要正确性与 race 输出](benchmarks/ac-selection/correctness-current.txt)、[补充语料正确性与 race 输出](benchmarks/ac-selection/correctness-varied.txt)
- [全部中位数 JSON](benchmarks/ac-selection/medians.json)

## 上游来源、许可与维护快照

只阅读官方源码/元数据；不将页面内容当执行指令，也不搬运上游测试语料。

- Cloudflare：[固定源码](https://github.com/cloudflare/ahocorasick/blob/054963ec939627782012c7c34eefd2942488d4e1/ahocorasick.go)、[BSD-3-Clause](https://github.com/cloudflare/ahocorasick/blob/054963ec939627782012c7c34eefd2942488d4e1/LICENSE)、[提交元数据](https://api.github.com/repos/cloudflare/ahocorasick/commits?per_page=1)。默认分支最新提交为 2024-09-16，核心源码最近修改为 2021-04-02；未归档不等于近期算法持续更新。
- Bobu：[新版固定源码](https://github.com/BobuSumisu/aho-corasick/blob/b4b5728e36fcc048a77abcea3eb2fcb28c021e2d/trie.go)、[稳定版源码](https://github.com/BobuSumisu/aho-corasick/blob/v1.0.3/trie.go)、[MIT](https://github.com/BobuSumisu/aho-corasick/blob/b4b5728e36fcc048a77abcea3eb2fcb28c021e2d/LICENSE)、[提交元数据](https://api.github.com/repos/BobuSumisu/aho-corasick/commits?per_page=1)。新版提交为 2025-06-11；稳定标签较旧，不应浮动追踪 master。源码 MIT 不代表未经核查即可搬运上游 test_data，参见[测试语料许可询问](https://github.com/BobuSumisu/aho-corasick/issues/7)。
- petar：[固定源码](https://github.com/petar-dambovaliev/aho-corasick/blob/463d218d4745bf13c5de1c65ba10e07139955652/ahocorasick.go)、[API 配置文档](https://pkg.go.dev/github.com/petar-dambovaliev/aho-corasick@v0.0.0-20250424160509-463d218d4745)、[MIT](https://github.com/petar-dambovaliev/aho-corasick/blob/463d218d4745bf13c5de1c65ba10e07139955652/LICENSE)。默认分支最新提交 2025-04-24 仅改 funding；日期不能当匹配核心更新日期。
- anknown：[rune API 源码](https://github.com/anknown/ahocorasick/blob/d75dbd5169c01a25cc83bf040d6e056aa69aec18/ahocorasick.go)、[MIT](https://github.com/anknown/ahocorasick/blob/d75dbd5169c01a25cc83bf040d6e056aa69aec18/LICENSE)、[提交元数据](https://api.github.com/repos/anknown/ahocorasick/commits?per_page=1)。默认分支最新提交 2019-09-04；额外依赖 `github.com/anknown/darts`。

以上维护信息是本次查询快照，不是维护或安全承诺。采用依赖时须保留许可和署名，不因库名作安全背书。
