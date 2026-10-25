# 初始版本验证记录

工具链：Go 1.26.3 linux/amd64。

初始验证环境限制 TCP socket 与外网 DNS。vet、构建及集成测试编译通过；需要 TCP listener 的全包测试未能完整执行，不能据此宣称全部测试通过。排除依赖 listener 的用例后，单元和 race 测试通过。

规则和字典使用固定快照做离线校验。外部 Python Cookie 服务、真实付费 API 及远端资源下载未完成验证。初始环境结论不代表后续版本的验证结果；来源与许可条件见 [SOURCES.md](SOURCES.md)。
