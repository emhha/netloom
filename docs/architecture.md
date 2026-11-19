# 架构与目录职责

Netloom 是单一 Go module。根包提供网络运行时，子包按能力独立组织；不使用 TypeScript monorepo 式的 `apps/`、`packages/` 分层，也不把公共 Go 包塞入 `internal/`。

## 依赖方向

```text
probe / dirscan / nethttp ───────────────> netloom（根包）
passive/plugins ────────────────────────> passive + fingerprint / infoextract
fingerprint / infoextract / passive ────> httpdata
infoextract / passive/plugins ──────────> ac
httpdata/netloomdata ───────────────────> netloom + httpdata
traffic ───────────────────────────────> netloom + mitm + passive + httpdata/netloomdata
mapping / enterprise ──────────────────> httpclient
geoip / mitm ──────────────────────────> 标准库与各自外部依赖
```

这是主要依赖关系，不是完整 import 清单。实际依赖以 `go list -deps ./...` 为准。根包不依赖扩展；`httpdata` 不依赖网络运行时。需要分析网络结果时，在 `httpdata/netloomdata` 显式复制，而不是让离线分析器接收运行中的连接或共享请求状态。

`ac` 是 Cloudflare ahocorasick 固定版本的薄适配层，可独立使用，归一化空词/重复词并统一走线程安全的唯一词集合扫描；不另行维护一套自动机。fingerprint 原有匹配内核保持独立，不迁入该共享层。`infoextract` 使用它筛选触发词后运行正则，既可直接使用，也可通过既有 `plugins.Information` 接入被动分析。`plugins.Serialization` 自行使用共享 AC 筛选文本规则候选，只对候选执行正则；安全固定字面量可直接命中，无法安全触发的规则保留 fallback，二进制 magic 仍做前缀检查。Registry 负责插件调度与缓存，不强制所有插件使用 AC；是否选择共享引擎属于各插件的实现决策。

`httpclient` 面向第三方 API，与根包的 TLS 指纹传输不是同一个客户端。两者分别拥有重试、限流、TLS 和响应体策略；不能仅为复用而强行统一默认行为。仅纯本地代理 URL 解析与安全错误由 `internal/proxyconfig` 共享，各客户端独立选择支持的 scheme，解析不触发 DNS 或网络。数据源适配器依赖小型调用方接口取得凭据，不内置凭据存储服务。

## 目录职责

| 位置 | 职责 |
| --- | --- |
| 根目录 Go 源码 | 配置、请求/响应、Engine、Transport、Pipeline、调度、限流、TLS、重定向与流式生命周期 |
| `httpdata/` | 离线证据模型；`netloomdata/` 是运行时复制适配器 |
| `ac/` | 公共字节串 Aho-Corasick 匹配引擎，不依赖 HTTP 模型或运行时 |
| `fingerprint/`、`infoextract/`、`passive/` | 离线分析；内置插件在 `passive/plugins/` |
| `traffic/` | 组合主动请求和 MITM，解析入口代理，采集证据并调度调用方选择的插件 |
| `probe/`、`dirscan/` | 主动探测；授权和任务持久化归调用方 |
| `nethttp/`、`mitm/`、`geoip/` | 请求转换、代理原语、本地 IP 信息 |
| `httpclient/`、`mapping/`、`enterprise/` | API 会话与数据源适配 |
| `examples/` | 可编译的调用示例，不是正式 CLI |
| `scripts/` | 仓库检查与明确触发的资源更新工具 |
| `docs/` | 安装、API、开发、测试、验证与来源许可说明 |

测试跟随被测包；集成测试通过 `integration` build tag 隔离。指纹规则和目录字典留在能力所属目录，不搬入 `testdata/`：它们是显式 opt-in 的运行时资源，而非仅测试夹具。来源清单和第三方许可必须随资源保留。

## 生命周期与调用方责任

根包的 Upload/Multipart 仅管理显式 reader 的懒打开/关闭和重放能力；不会为了重试缓存任意正文。RetryPolicy 共享 Send/Run 的尝试决策，Auth 在单次尝试内进行有界 origin 挑战；不让第三方客户端隐式打开额外重放源。Session 是可注入、host 隔离、有界且可清理的内存状态，缓存连接使用动态 facade，不持有已淘汰 jar。Raw 不进入这些普通请求变换。

`dirscan` 使用 `Engine.Send` 的独立准入路径，不通过根包任务 Pipeline 调度。每目录固定 worker 仅发送请求；单协调器按派发顺序处理分类、过滤、去重和发现队列。有界窗口同时计算在途与完成但未聚合的响应，以避免乱序响应积压；目录之间串行。扫描返回前取消并等待在途任务退出；字典、发现集合和结果总量不属于该窗口预算，完整契约见 [目录扫描](../dirscan/README.md)。

Engine 管理请求、队列、活动流和取消；调用方管理 Engine 的创建与关闭。调度器先初始化后发布，种子 feeder 也持有 pending 保活登记；Run 的活动登记覆盖 worker 退出和结果通道关闭。主机并发槽按持有者/等待者共同引用计数，无引用即回收；错误/跳过历史归单次 Run 所有，不做会改变阈值语义的活动中淘汰。流式响应体必须关闭，Pipeline 不得在自己的工作线程内同步关闭所属 Engine。具体零值、背压和关闭约束由 [API 与配置](API.md) 定义。

MITM 提供 CA、CONNECT、转发和观察原语，不自动启动监听或安装系统证书。GeoIP 读取明确指定的资源目录，只有显式 Update 才下载。SDK 不提供数据库、ORM、Web 服务、后台任务系统或流量/凭据持久化。

## 结构变更原则

- 新能力优先加入职责明确的子包；仅在确有跨包私有实现时引入 `internal/`，不提前建立空目录。
- 保持离线模型可独立使用；不要给 `httpdata` 增加运行时依赖。
- 不用文件移动掩盖 API 变更。公开包路径、配置默认值及可见错误变化必须写入 [升级说明](UPGRADING.md)。
- 当前事实写入所属文档；公开上游来源、资源版本、校验哈希与许可信息按 [来源与许可](SOURCES.md) 保留，不进行品牌替换。
