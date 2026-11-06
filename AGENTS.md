# Netloom 开发约定

## 入口

修改前阅读 [架构](docs/architecture.md)；命令见 [开发指南](docs/development.md)，测试分类见 [测试说明](docs/testing.md)，文档入口为 [docs/README.md](docs/README.md)。

## 代码与边界

- 单一 Go module `github.com/emhha/netloom`；根包 `netloom`，扩展保持公共子包。
- 根包不依赖扩展，`httpdata` 不依赖运行时；证据转换使用 `httpdata/netloomdata`。API 查询 `httpclient` 不强行复用扫描客户端默认值。
- 不引入数据库、应用服务、隐式用户目录发现、自动私钥/流量持久化；网络资源更新必须由调用方明确触发。
- 保留现有工作区修改；不自动修改其他项目，不擅自提交或发布。
- 行为变更同时更新相邻测试与所属文档；公开包路径、默认值、可见错误变化写入 [升级说明](docs/UPGRADING.md)。

## 文档与验证

- 文档仅描述独立 SDK 的用途、接口与维护方式，不发布私有项目背景、部署信息、工作区记录或下游集成计划。
- README 提供入口，架构描述职责，包说明定义本包行为，开发/测试说明操作。
- 保留公开上游资源的来源、版本、校验哈希与许可证；不得以文档清理为由删除必要的作者或许可声明，也不对第三方原始内容进行品牌替换。
- 运行相关测试；仓库级改动执行 `make check`、`make race` 和 `make integration-compile`。记录真实结果和环境限制，不把跳过当通过。
- 校验脚本依赖 Python 标准库；新增可机械检查的结构约定时加入现有仓库检查及离线回归测试，避免只写规则而不执行。
