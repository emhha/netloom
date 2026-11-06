# 验证记录

## 验证范围

正式 module 路径为 `github.com/emhha/netloom`，根包仍为 `netloom`。本记录仅描述独立 SDK 的验证结果；发布与远程服务不属于本地测试的证明范围。

工具链：Go 1.26.3 linux/amd64、Python 3.14.8。

完整命令：

```sh
GOCACHE=/tmp/netloom-go-cache make check race integration-compile integration-local
git diff --check
```

## 本轮结果

上述完整命令退出码为 0。

| 检查 | 结果 |
| --- | --- |
| `make check` | 通过：格式、维护中文档链接和隐私约束、module/包边界、17 个 Python 离线测试、50 个固定字典文件校验、全包单元测试、vet、构建 |
| `make race` | 全包通过，无已报告数据竞争 |
| `make integration-compile` | 所有 integration 用例编译通过，不能据此声称执行过外部服务 |
| `make integration-local` | 通过；明确排除外部 Python Cookie 服务用例 |
| `go mod tidy -diff`（离线） | 通过，无依赖文件差异 |
| 独立调用方导入 | 使用本地源码离线导入根包、`httpdata` 和 `httpdata/netloomdata`，创建/关闭 Engine，测试通过；不证明远程可获取性 |
| `git diff --check` | 通过 |

构建期间出现模块统计缓存只读的非致命警告，相关命令仍退出 0；未为消除警告而修改全局 Go 配置。固定资源的原始字节、校验值及许可证保持不变。

## 覆盖边界

- 集成编译不等于执行；`integration-local` 显式排除需要外部 Python Cookie 服务与固定 DNS 的用例。
- 不调用真实付费 API，不使用实际服务凭据；mapping 包尚无包内协议测试，不能把编译成功当作服务验收。
- 不捆绑或下载第三方 MMDB；真实数据内容、城市/ASN/Country 查询仍需使用具备许可的数据另行验证。
- 规则与字典固定快照可离线校验；本地测试不证明远端版本可达、最新或具备再分发授权。
