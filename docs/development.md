# 开发指南

## 环境

- Go 1.26.0+；模块版本由 `go.mod` 决定，当前验证工具链见 [验证记录](VALIDATION.md)。
- Python 3：文档/仓库检查和字典更新脚本使用标准库，不需要安装 pip 依赖。
- Git：脚本测试和来源快照更新需要；Make 是命令快捷入口，不是编译依赖。

从仓库根目录运行命令。依赖下载使用常规 Go module 机制，不提交开发机绝对路径、临时 `replace` 或替身实现。缓存目录只读时可为当前命令指定可写的 `GOCACHE`；不要为了开发修改全局 Go 配置。

```sh
go mod download
make check
```

## 常用命令

`make help` 显示完整入口。工具可覆盖，例如 `make GO=/path/to/go PYTHON=python3 check`。

| Make 目标 | 作用 |
| --- | --- |
| `fmt` / `fmt-check` | 格式化 / 检查所有维护中的 Go 文件 |
| `test` | `go test ./...` |
| `vet` / `build` | `go vet ./...` / `go build ./...` |
| `race` | `go test -race ./...` |
| `integration-compile` | 编译带 integration tag 的测试但不执行 |
| `integration-local` | 执行本地集成测试，明确排除外部 Python Cookie 服务用例 |
| `integration` | 执行集成测试；先满足 [前置条件](testing.md) |
| `docs-check` | 本地 Markdown 链接、模块命名和包布局检查 |
| `scripts-test` | Python 脚本离线测试 |
| `wordlists-check` | 验证固定字典的校验清单 |
| `check` | 格式检查、文档/脚本/字典检查、测试、vet、构建 |

不使用 Make 时：

```sh
python3 scripts/check-repository.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/update-dirsearch-wordlists.py --check
go test ./...
go vet ./...
go build ./...
go test -race ./...
go test -tags=integration ./... -run '^$'
```

`check` 不执行集成网络请求、不更新资源、不发布仓库。CI 运行同一组入口及 race、集成编译和本地集成测试；真实外部服务测试由具备环境的调用方明确触发。

## 修改流程

1. 阅读 [架构](architecture.md)，确认包职责、依赖方向及公开行为。
2. 保留已有工作区变更；修改实现和相邻测试，不顺便覆盖其他项目或上游快照。
3. 使用 `gofmt`；按变更范围执行测试。仓库级路径调整应执行全包检查。
4. 更新所属包的说明和 [API 文档](API.md)。公开导入路径、默认值或错误文本变化同时更新 [升级说明](UPGRADING.md)。
5. 提交前运行 `make check`；并发相关变更运行 `make race`。记录实际命令、失败原因和未验证范围，不能用跳过的测试冒充通过。

## 文档与资源维护

README 负责入口，架构说明依赖和目录职责，包 README 说明本包配置与限制，开发/测试指南说明操作，验证记录保存带日期的证据。不要把执行过程写进当前 API 说明，也不复制多份默认值表。

第三方资源的来源、版本、校验哈希、原始 README 和许可声明须保留，不因项目名称或导入路径变化替换内容。资源更新遵循 [字典维护说明](../dirscan/wordlists/README.md) 和 [规则说明](../fingerprint/rules/README.md)。公开文档不记录私有工作区、部署或其他项目的集成安排。

module 路径统一为 `github.com/emhha/netloom`。正式发布前须完成来源权利与资源许可核实，并执行相应测试；详情见 [来源与许可](SOURCES.md) 和 [安装与使用](MIGRATION.md)。
