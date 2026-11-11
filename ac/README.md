# ac：公共字节串关键词集合匹配

`github.com/emhha/netloom/ac` 是 [Cloudflare ahocorasick](https://github.com/cloudflare/ahocorasick) 的薄适配层，固定依赖版本 `v0.0.0-20240916140611-054963ec9396`。不自行实现 trie、failure links 或转移表。适合离线正文、协议字段和二进制内容的候选词预筛选；选型依据与可复现实测见 [AC 库选型](../docs/AC-SELECTION.md)。

```go
import "github.com/emhha/netloom/ac"

keywords := []string{"", "he", "she", "he", "\x00\xff"}
matcher := ac.New(keywords)
hits := matcher.Search([]byte("she\x00\xff")) // he、she、\x00\xff 的集合
matcher.Match([]byte("she he"), func(index int) {
    // 下标集合为 {1, 2}，每个只回调一次；不承诺顺序。
    _ = keywords[index]
})
_ = hits
```

## API 与行为

- `New(keywords []string) *Matcher`：构建一次、重复使用；不保留调用方输入切片。空词忽略，相同字节串去重；重复词保留第一次出现的原始下标，不重新编号。
- `(*Matcher).Search(text []byte) map[string]struct{}`：返回出现过的关键词集合。无命中也返回非 nil 的独立 map；调用方可自由修改结果。
- `(*Matcher).Match(text []byte, hit func(index int))`：同步回调命中唯一词的原始下标，每个词每次调用最多回调一次。完整保留重叠词及后缀词，但**不承诺回调顺序、出现次数或位置**。它是候选集合接口，不是逐 occurrence 枚举器。`hit == nil` 时直接返回，不扫描。
- 区分大小写，不做 Unicode 解码、规范化或大小写转换。NUL、0xff 和非法 UTF-8 都是普通字节。空文本不命中。
- 零值 `Matcher`（以及 nil `*Matcher`）安全且不产生命中。
- 多个 goroutine 可并发调用 `Search` / `Match`，内部扫描统一使用上游 `MatchThreadSafe`，不暴露或混用上游非线程安全的 `Match`。字典构建后固定；上游仍有内部原子计数器与池化扫描状态。扫描期间不修改字典。
- 回调中的外部共享状态由调用方同步；输入字节切片在调用期间不得被并发修改。

## 使用与性能边界

规则应保存“唯一词 → 一或多个候选规则”的映射，不要用重复词创建互相覆盖的规则 ID。AC 命中只说明触发词存在，正则、上下文、scope、长度和输出顺序仍由业务规则决定；没有可证明必要触发词的规则不能直接跳过。

`Match` 省去调用方字符串集合，适合直接生成候选 bitset，但上游仍会分配命中下标切片；不是零分配接口。无命中热池可能不分配，首次扫描、GC 丢弃池状态或并发扩张时仍可能分配 map。`Search` 另需独立的结果 map。

Cloudflare 使用较大的密集指针转移表，当前小词表下吞吐较好，但每状态内存较大。不要逐请求构建自动机，也不要将小词表结论推广到无界词表；关键词规模显著增长时应重新测量保留堆、构建成本和实际语料。扫描不提供提前终止或跨调用流式状态，也不执行解码、正则、解压或网络访问。

## 验证

```sh
go test ./ac ./infoextract
go test -race ./ac ./infoextract
go test ./ac -run '^$' -bench . -benchmem
```

测试包含固定随机种子的任意字节输入与 `bytes.Contains` 集合/原始索引等价性、重复/空词、大小写、后缀/重叠、零值、输入/输出隔离与并发读。基准分别覆盖构建、无命中/稀疏/高密度正文的 `Match`、`Search`，并提供逐词存在性基线，不比较 occurrence 数量。

上游采用 BSD-3-Clause，来源、固定版本和校验索引见 [来源与许可](../docs/SOURCES.md)。
