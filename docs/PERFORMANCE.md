# 原生指纹匹配性能

本页保留原生指纹匹配的独立测量。共享 Cloudflare AC 的插件级测量另见 [Serialization 性能记录](PERFORMANCE-serialization.md)，不将两套内核或基准混为一谈。

本次只优化 EHole 与 FingerprintHub，规则文件和启用配置保持不变。保留优化前的线性实现于 native_linear_test.go，用作独立回归及性能对照；生产路径不保留两套可选实现。

## 实现

- 在规则加载时构建按 body/header/title/all 和大小写模式划分的 Aho-Corasick 索引，单次扫描生成命中集合，再用集合核对 AND/OR。状态使用紧凑双数组和失败链接，逐字节转移不查询 Go map，也不展开 256 列的完整 DFA。
- 图标 MD5/mmh3 直接定位候选规则，规则原始顺序和多规则合并行为保留。
- 从 Go 正则语法树提取能证明必需的字面量。候选预筛选后核对全部必需字面量，再执行原正则。可选分支/分支选择、空匹配、替换字符等无法安全筛选的情况退回原正则，不用近似匹配替代正则。Unicode 简单折叠单独处理，避免 ſ/K 等字符造成漏报。
- 正文和响应头转换、大小写规范化在单次调用内共享；重复的请求方法/路径/请求头约束只计算一次。缓存不存于 Engine，不跨请求复用可变数据。匹配过程不再为每个 pattern 创建 bool 切片。

## 测量方法

Go 1.26.3、linux/amd64，固定 -cpu=4。使用仓库的完整 958 条 EHole 和 3,425 个 FingerprintHub 模板，构建索引后比较单独匹配器，不包含网络、Wappalyzer、磁盘读取及规则初始化；两边均包含相同 MatchContext 构造。测试与 race 完成后单独执行基准，未并行运行其他本任务测试。

正文长度精确为 4/64/256 KiB；无命中样本为重复的普通 HTML 片段。64 KiB 混合命中样本包括实际关键词组合、HTML title、nginx 响应头和已捕获图标哈希。每个子项运行三次，表中取各指标中位数。较慢的旧实现每次可能仅有一个迭代，数字是本机样本观测，不是统计显著性或真实网站吞吐量承诺。

```sh
GOCACHE=/tmp/netloom-go-cache GOPROXY=off go test ./fingerprint \
  -run '^$' -bench 'BenchmarkNativeMatchers|BenchmarkNativeMatcherBuild' \
  -benchmem -benchtime=100ms -count=3 -cpu=4
```

## 匹配结果

分配列是每次调用累计分配字节（B/op），不代表峰值或驻留内存。

| 来源 | 样本 | 线性 ms/op | 索引 ms/op | 相对速度 | 累计分配：旧 → 新 |
| --- | --- | ---: | ---: | ---: | --- |
| EHole | 4KiB | 0.356 | 0.034 | 10.6× | 12.6 KiB → 9.6 KiB |
| FingerprintHub | 4KiB | 39.893 | 0.078 | 510.0× | 16.59 MiB → 12.1 KiB |
| EHole | 64KiB | 4.647 | 0.261 | 17.8× | 72.6 KiB → 69.6 KiB |
| FingerprintHub | 64KiB | 507.078 | 0.850 | 596.8× | 241.27 MiB → 72.1 KiB |
| EHole | 256KiB | 18.062 | 0.941 | 19.2× | 264.7 KiB → 261.6 KiB |
| FingerprintHub | 256KiB | 2551.557 | 3.650 | 699.0× | 960.49 MiB → 264.1 KiB |
| EHole | 64KiB-mixed-hit | 5.251 | 0.387 | 13.6× | 141.1 KiB → 138.3 KiB |
| FingerprintHub | 64KiB-mixed-hit | 998.083 | 1.407 | 709.5× | 418.56 MiB → 281.5 KiB |

## 一次性初始化成本

加载时会解析 JSON、编译正则并构建索引；应复用 Engine，避免每个请求都重新初始化。以下为当前完整加载的测量，并非相对旧版的加载加速比较。累计分配含构建时临时对象，不等于索引最终占用。

| 来源 | ms/次 | 累计分配/次 |
| --- | ---: | ---: |
| EHole | 21.6 | 5.91 MiB |
| FingerprintHub | 269.0 | 79.92 MiB |

## 结果等价性与边界

冻结线性实现逐项对照结果，包括顺序、名称、来源、版本和置信度；覆盖实际语料样本、固定随机种子的匹配组合、否定、图标部分缺失、大小写、Unicode 简单折叠和非法 UTF-8、空匹配、可选/重复/分支、请求约束、截断、并发及取消。双数组 AC 另与普通子串搜索对照随机字节、重叠和后缀命中。

相关回归、race 与 go vet 通过。完整默认测试中的既有 TCP socket 用例仍受当前沙箱限制，性能测试自身全部离线。

候选较密集、正则没有可提取的必需字面量、或文本包含大量匹配时，加速比会变化；索引不会省略最终条件判断。默认启用仍为 EHole/FingerprintHub/Wappalyzer，webfinger 禁用，公共配置与分析接口不变。

原始测量输出见 [PERFORMANCE-native-benchmark.txt](PERFORMANCE-native-benchmark.txt)。输出保留测量时的包标识，不代表当前导入路径；未为重命名而改写原始测量数据。
