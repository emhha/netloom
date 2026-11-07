# 测试说明

## 默认测试

```sh
go test ./...
go vet ./...
go build ./...
```

默认测试不要求真实数据源凭据或付费查询，但部分传输、代理、HTTP 会话和 GeoIP 更新用例会启动本地可控 HTTP/TLS 服务，因此需要允许本机 TCP socket。Go module 依赖首次构建前也需要准备齐全。`mapping` 当前没有包内协议测试，构建通过不代表已验证第三方服务行为。

`fingerprint` 使用仓库随附规则做离线加载、等价性和匹配测试；不主动扫描外网。字典测试使用固定快照，不应联网更新。

## HTTP 可靠性回归

```sh
go test . -run '^Test(Reliability|PartialResponse)' -count=1
```

这些默认测试使用 fake transport 或本地可控 HTTP/TLS 服务，覆盖请求/配置/context 超时（含正文阻塞与亚毫秒期限）、失败时的部分响应、重试后证据保留、实际 TLS 连接次数与证书、流式 EOF/提前关闭/读取失败状态，以及 Engine.Close 中断读取。它们不访问外网，不替代真实代理/外部目标验收。流式状态并发读取和关闭路径同时由 race 检查。

## 连接池与 HTTP/2 回归

```sh
go test -race . ./nethttp -run 'Test(ConnectionPool|ClientDialScope|HTTP|BuildRequest)' -count=5
```

本地服务覆盖 H1/H2 缓冲与流式顺序复用、实际 IP/证书/缺失阶段 timings、默认不复用与按次 FreshConnection、origin/验证开关/代理超时隔离、自定义 Profile/信任根一次性使用、客户端容量/空闲 LRU/TTL、等待取消、EOF 租约所有权、失败释放、Cookie 会话与客户端驱逐的独立生命周期，以及 Engine.Close 实际关闭空闲 socket。严格 H2 用例检查 ALPN 失败前无 HTTP/1 请求，含明文/无 ALPN/H1-only 目标、自定义信任/mTLS 和代理/取消；HTTP CONNECT 用例验证早期限/显式取消/Engine.Close 后 socket 关闭、认证不泄漏、响应头上限及预读字节保留。过期 H2 重连用例先完成真实 H2 请求、断开旧连接，再阻塞新 TLS 握手，检查缓冲/流式的超时、取消和 Close 不因依赖的后台 context 而卡住。ClientDialScope 另测旧 lease 取消不误关空闲连接及过时 dial 不可归入新 lease。这些不是外部网络或性能验收。

## 阶段超时与结构化错误回归

```sh
go test -race . ./nethttp -run 'Test(Phase|BuildRequestPhase|ConnectionPoolStaleHTTP2|HTTPProxyCONNECT)' -count=5
```

本地 H1/H2/严格 H2 覆盖 POST 后完整响应头超时、103/不完整最终响应头、部分正文 idle 失败与流式 Status、调用方暂停消费不误计 idle、持续进展的正文不被固定 body 时长截断、TLS stall（含大写 HTTPS scheme）、真实过期 H2 重新握手、CONNECT 阻塞后的 socket 关闭与池容量释放。另测连接复用不重新计算 TLS 预算、晚到 WroteRequest 不复活已结束的 header timer、整组策略继承/显式零覆盖、负值和毫秒换算溢出、调用方提前 deadline/取消 cause、Raw TLS/header/body/部分响应，以及 Total 跨重试和 Do 多跳不重置。Connect 的模拟拨号用例检查依赖 Background context 被当前 lease ctx 替换；真实 socket 取消由 TLS/CONNECT 用例检查，不依赖不可控外网黑洞地址。这不是精确 TLS 握手时长、外部代理、浏览器等价性或性能验收。

## 并发检查

```sh
go test -race ./...
```

需要支持 race 的 Go 工具链、CGO 和 C 编译器。涉及 Engine 关闭、调度、缓存、流式响应、Cookie 或 GeoIP reload 的修改应运行相关包的 race 测试；重命名或依赖调整后建议全包执行。

## 集成测试

```sh
# 只验证所有带 integration tag 的测试能够编译
go test -tags=integration ./... -run '^$'

# 执行本地集成测试，明确排除外部 Cookie 服务
make integration-local

# 全量执行；先确认以下环境条件
go test -tags=integration ./...
```

根包的 TLS/mTLS、代理和流关闭集成测试使用本地服务。Python Cookie 测试需要单独准备受控服务：端口 9099、测试要求的 Cookie/跳转响应，以及 probe 包使用的 `cookie.test` / `other.test` DNS 映射。仓库不提供该服务的启动程序，具体协议以测试断言为准。

没有准备服务时 Cookie 用例会跳过，不能把 `go test` 的成功退出当作这些场景的执行证据。不要为了让 probe 用例通过而关闭生产拨号防护或自动修改 `/etc/hosts`。调用方应按测试中描述的协议准备受控服务，再运行对应测试。CI 执行集成编译与 `integration-local`：后者明确排除名为 `TestPythonCookieServerE2E` 的两个外部服务用例，不假称执行过外部 Cookie 服务。本地 TLS/代理/流关闭集成仍会真实运行。

## 仓库与资源检查

```sh
python3 scripts/check-repository.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/update-dirsearch-wordlists.py --check
```

仓库检查覆盖维护中文档的相对链接、Go 模块/包命名、旧导入残留、包布局及格式。上游 README、许可证和第三方原始资源不是品牌替换或文档链接修复目标。字典更新脚本的测试只在临时 Git 仓库中操作，不改动外部仓库。

## 验证结果的记录方式

在 [验证记录](VALIDATION.md) 中追加日期、工具链、实际命令、结果及限制；不要覆盖旧日期的环境证据。测试失败先区分实现失败、依赖准备失败和环境限制。确需跳过时写出精确命令与缺失覆盖，不在默认入口永久跳过失败用例。

真实 MMDB 查询需要调用方合法提供数据库；单元测试的生命周期和错误路径不能替代真实数据库内容验收。真实数据源认证、配额与收费接口也不属于默认测试，需单独获得授权。

性能基准单独执行，避免与 race/全量测试争抢资源；命令和历史测量见 [指纹性能记录](PERFORMANCE.md)。
