# Netloom 文档

## 使用

- [项目首页](../README.md)：定位、快速开始和能力概览。
- [安装与使用](MIGRATION.md)：模块安装、导入和生命周期。
- [示例](../examples/README.md)：请求、流式与 Pipeline。
- [API 与配置](API.md)：核心默认值、所有权、背压和扩展契约。
- [流式上传与请求契约](REQUEST-BODIES.md)：reader/multipart、重放、有界证据及普通/Raw 边界。
- [内存会话](SESSIONS.md)：注入、host 隔离、容量/过期和清理。
- [重试与观察](RETRIES.md)：方法安全、退避、Retry-After 和 attempt 回调。
- [认证](AUTHENTICATION.md)：Basic/Digest、挑战扩展及凭据边界。
- [本地源 IP 与 Linux 网卡绑定](NETWORK-BINDING.md)：按请求绑定、地址族、权限、错误与池生命周期。
- [升级说明](UPGRADING.md)：公开导入路径与可见行为变化。

## 架构与开发

- [架构](architecture.md)：目录职责、依赖方向和扩展原则。
- [开发指南](development.md)：工具链、命令和修改流程。
- [测试说明](testing.md)：默认测试、race、集成环境和证据要求。
- [HTTP/HTTPS 能力计划](HTTP-CAPABILITIES-PLAN.md)：对标 libcurl 的分阶段传输能力与验收边界。
- [贡献指南](../CONTRIBUTING.md)：变更范围与提交检查。
- [安全使用](../SAFETY.md)：TLS、代理、凭据、MITM 和目标授权边界。
- [验证记录](VALIDATION.md)：实际运行结果与未验证范围。
- [性能记录](PERFORMANCE.md)：原生指纹的可复现测量。
- [Serialization 性能](PERFORMANCE-serialization.md)：共享 Cloudflare AC 接入后的完整插件与文本分层测量。
- [AC 库选型](AC-SELECTION.md)：信息提取/序列化预筛选的语义、并发、内存和实测比较。

## 包与资源

- [HTTP API 会话](../httpclient/README.md)：API 重试、限流、代理和 TLS 策略。
- [测绘数据源](../mapping/README.md)：FOFA、Hunter、Quake 适配与凭据接口。
- [企业信息](../enterprise/README.md)：企业数据源接口与 Aiqicha 适配。
- [GeoIP](../geoip/README.md)：本地 MMDB/CDN 资源与显式更新。
- [共享 AC 匹配](../ac/README.md)：独立字节串匹配引擎与关键词索引回调。
- [信息提取](../infoextract/README.md)：独立调用、触发词/正则与 Information 插件。
- [内置被动插件](../passive/plugins/README.md)：显式注册、Serialization 的解码预算和结果边界。
- [指纹规则](../fingerprint/rules/README.md)：来源、配置和支持范围。
- [目录字典](../dirscan/wordlists/README.md)：固定快照、校验和更新。

其他包的导出 API 以 Go 注释为准，可运行 `go doc ./probe`、`go doc ./passive` 或相应包路径查看；跨包行为见 [API 说明](API.md)。

## 来源与许可

- [来源与许可](SOURCES.md)：第三方来源、发布前权利核实和资源限制。
- [许可文本](../LICENSE)：适用许可；资源附带的独立许可声明仍须遵守。

文档按读者任务分工：入口保持简短，当前行为归所属参考文档，验证结果单独记录。公开上游资源的作者、来源、版本和许可信息应随资源保留。
