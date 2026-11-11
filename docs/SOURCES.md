# 来源与许可

## SDK 代码

本仓库保留 [GNU AGPL v3 许可文本](../LICENSE)，未将代码或资源重新声明为 MIT、Apache 等其他许可。部分实现的原始授权及再分发条件尚待核实；保留许可文本不代表所有内容的权利审查已经完成，公开发布前仍需确认授权与署名要求。

适配前文件的校验记录见 [来源校验索引](provenance/README.md)。这些哈希用于区分原始基线与适配结果，不代表当前文件的校验值，也不构成许可授权。库内的小型信息提取规则保留原有规则名称和源码中的公开来源声明。

## 可选指纹资源

资源由调用方显式加载，不会自动下载或嵌入二进制。使用方式见 [指纹资源说明](../fingerprint/rules/README.md)。

| 资源 | 公开来源与固定记录 | 许可边界 |
| --- | --- | --- |
| webfinger | [jjf012/webfinger](https://github.com/jjf012/webfinger)，固定提交、Git blob 与 SHA-256 记录在 [upstream.json](../fingerprint/rules/upstream.json) | 保留 [原始 README](../fingerprint/rules/README.upstream.md)；现有来源快照未附明确许可，使用及再分发前须核实 |
| Wappalyzer | [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)，版本和 SHA-256 记录在 [wappalyzer.upstream.json](../fingerprint/rules/wappalyzer.upstream.json) | 保留 [原始 README](../fingerprint/rules/README.wappalyzergo.md) 和 [MIT 许可](../fingerprint/rules/LICENSE.wappalyzergo.md) |
| EHole / FingerprintHub | [EHole](https://github.com/EdgeSecurityTeam/EHole) / [FingerprintHub](https://github.com/0x727/FingerprintHub)，文件来源和 SHA-256 记录在 [native-sources.upstream.json](../fingerprint/rules/native-sources.upstream.json) | 现有快照未附完整提交和许可信息，不虚构版本、不重新许可；再分发前须核实 |

EHole 与 FingerprintHub 的解析、索引和匹配由本库实现，不引入对应扫描 SDK；这不改变规则文件自身的许可条件。

## 可选目录字典

[dirsearch 字典](../dirscan/wordlists/README.md) 固定提交、Git tree 和逐文件 SHA-256 记录在 [upstream.json](../dirscan/wordlists/dirsearch/upstream.json)。

字典保留 [上游 README](../dirscan/wordlists/dirsearch/README.upstream.md)、[打包元数据](../dirscan/wordlists/dirsearch/PACKAGING.upstream.txt) 和 [GPL v2 许可文本](../dirscan/wordlists/LICENSE-GPL-2.0.txt)。上游 README 声明 GNU GPL version 2，打包元数据标记 GPL-2.0-only；本仓库不将这些资源重新声明为 AGPL。

## 外部依赖和数据

Go 依赖由 [go.mod](../go.mod) 和 [go.sum](../go.sum) 固定版本，各依赖保留自身许可证。可执行 `go list -m all` 查看依赖清单。

共享 `ac` 包薄适配 [Cloudflare ahocorasick](https://github.com/cloudflare/ahocorasick)，固定版本 `v0.0.0-20240916140611-054963ec9396`，对应提交 `054963ec939627782012c7c34eefd2942488d4e1`。上游版权为 CloudFlare, Inc.，采用 [BSD-3-Clause](https://github.com/cloudflare/ahocorasick/blob/054963ec939627782012c7c34eefd2942488d4e1/LICENSE)，保留[原许可文本](../ac/LICENSE.cloudflare)。不复制或重署名其匹配内核；源代码及二进制再分发须遵守原许可的版权、条件与免责声明要求。Go module 校验值为 `h1:W2HK1IdCnCGuLUeyizSCkwvBjdj0ZL7mxnJYQ3poyzI=`，依赖清单校验值见 [go.sum](../go.sum)。接口及线程安全约束见 [ac 说明](../ac/README.md)，选型与测量见 [AC 库选型](AC-SELECTION.md)。

GeoIP 的 MMDB/CDN 数据由调用方自行提供；本仓库不捆绑第三方数据库。数据许可、下载授权和使用限制由供应方分别定义，不随 SDK 许可自动取得。
