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

## HTTP 可靠性第一阶段补充验证

工具链仍为 Go 1.26.3 linux/amd64、Python 3.14.8。实施范围见 [能力计划](HTTP-CAPABILITIES-PLAN.md)，公开行为见 [API](API.md) 和 [升级说明](UPGRADING.md)。

最终实现执行以下完整命令，退出码 0：

```sh
make check && make race && make integration-compile && make integration-local && git diff --check
```

| 检查 | 结果 |
| --- | --- |
| `make check` | 通过：格式、仓库/文档检查、17 个 Python 离线测试、50 个字典文件校验、全包测试、vet、build |
| `make race` | 全包通过，无已报告数据竞争 |
| `make integration-compile` | 所有集成测试编译通过 |
| `make integration-local` | 本地集成通过，包括自定义信任/mTLS、代理、流式生命周期；明确排除外部 Python Cookie 服务 |
| `git diff --check` | 通过 |

附加定向验证：

```sh
go test . -run '^Test(Reliability|PartialResponse)' -count=1
go test -race -tags=integration . -run '^Test(Reliability(BodyTimeout|ProxyBodyTimeout|SubMillisecondStreamTimeout|EngineCloseInterruptsBlockedRead)|ProxyIsUsedBySendAndStream)' -count=10
```

定向测试通过；最终直连/代理超时与关闭竞争用例在 race 下连续执行 10 次通过。fake transport 覆盖最近非 nil 响应、后续无 headers 失败、取消/地址阻止、重试成功、Run 证据及有效超时副本。本地服务覆盖配置/请求/context 期限、正文阻塞、亚毫秒期限、H1/H2 实际协议与单连接证书 SHA256、部分正文和流式完成状态；不访问外网。

中间验证曾暴露两个问题，均修复后重跑，而非跳过失败用例：客户端计时器与 context 同时到期导致读取错误原因不稳定；禁用客户端计时器时，依赖库 CONNECT 拨号器将零超时视作立即到期。最终由 context 管理精确期限，直连禁用独立客户端计时器，代理保留正值毫秒向上取整的兼容期限；读取失败按有效 context 期限归因。相关场景已加入回归。

早期检查曾因构建缓存只读被沙箱阻止，不能算通过；最终在允许写入缓存的执行环境完成以上命令。未修改全局 Go 配置，未运行外部 Cookie 服务、真实付费 API 或远程目标测试。

本阶段不证明连接池复用/隔离、显式 H2 策略、HTTP/3 或高级 DNS/路由能力已经实现。Raw 尚未提供普通路径的完整 Timings；缓冲 QueueMS 暂不测量。
