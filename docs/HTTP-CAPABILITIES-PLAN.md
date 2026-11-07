# HTTP/HTTPS 能力实施计划

## 目标与边界

以 Web 测试需求定义范围，以 libcurl 的 HTTP/HTTPS 能力模型核对传输控制和诊断完整性，不承诺兼容全部 libcurl 选项或 curl 命令行。参考 [libcurl easy](https://curl.se/libcurl/c/libcurl-easy.html)、[multi](https://curl.se/libcurl/c/libcurl-multi.html) 与 [getinfo](https://curl.se/libcurl/c/curl_easy_getinfo.html)。

核心运行时负责传输、资源生命周期与结果；文件路径、持久化、CLI 退出码、展示和任务授权归调用方。保留 TLS 验证开关、直连地址限制、跨 origin 凭据隔离，不引入隐式文件读取或资源更新。API 查询客户端与目标测试运行时保持独立。

## 阶段一：结果可靠性（已实现，验证见记录）

本阶段已落地；实际命令与覆盖边界见 [验证记录](VALIDATION.md)。阶段二分批交付，阶段三至五仍是后续计划。普通缓冲请求已补 Timings；Raw 暂保留既有耗时/TLS 字段，缓冲 QueueMS 暂未测量，缺失阶段继续保留 nil。

1. 统一 Send、Run、SendStream 的 timeout 优先级：请求正值覆盖 Engine 配置，配置缺省 10 秒；调用方更早的 context deadline 始终生效。传输层不得用隐式 10 秒总期限覆盖已选配置。固定 TCP 拨号超时暂不扩展为公开阶段参数。
2. Send、Run 和重定向保留失败前已收到的响应。重试失败返回最近一次非 nil 响应与最终错误，不声称该响应属于最终尝试；不在本阶段改变重试次数或方法策略。
3. 缓冲与流式路径使用实际连接的 trace/TLS 状态。删除补元数据的第二次 TLS 握手；无法测量的阶段保留缺失，不伪造证书或耗时。
4. 补全缓冲请求的 timings；流式提供线程安全的完成状态快照，包含读取字节数、EOF/提前关闭/读取失败、body 与总耗时。返回时的响应元数据不被后台并发改写；流式读取仍必须显式 Close 释放资源。
5. 相邻回归覆盖请求与配置超时、context deadline、部分响应/重试、单次 TLS 连接、EOF/提前关闭/取消、Engine.Close 与 race。

验收：相关单元/本地集成真实执行；仓库 make check、make race、make integration-compile；文档记录真实结果与环境限制。公开行为更新写入 [升级说明](UPGRADING.md)。

## 阶段二：连接与协议控制

已实现的阶段 2A：

- 显式启用、按 origin/代理/验证开关/协议隔离的有界客户端池，空闲 LRU/超时回收、按次禁止复用和 Engine.Close 回收。MaxClients 包含一次性租约，不承诺第三方后端全部 TCP socket 的严格总数。先采用独占租约/顺序复用，不宣称已实现同客户端 H2 并发复用。
- 仅隐式默认 Profile、TLSConfig=nil、直连或 HTTP CONNECT 代理缓存；其他代理 scheme 使用一次性租约。原始连接随当前租约取消，覆盖底层 H2 后台重连丢失 context 的情况。
- 自定义/显式指纹、信任根和 mTLS 在同一容量限制下一次性使用，避免不完整身份 key 导致连接串用。后续不可变 TLS/profile 身份与并发 multiplexing 仍待设计；Cookie 会话存储尚无独立容量上限。
- 显式 HTTP/2 策略：`2` 偏好并允许降级，`2-only` 在同一 HTTPS 握手的 ALPN 成功后才发 HTTP 请求。严格模式暂不复用，仅支持直连及 HTTP CONNECT 代理；覆盖不可用、代理与取消。非严格模式保留其他代理 scheme，但其第三方握手实时取消限制尚未解除。

后续阶段 2B（未实现）：

- 阶段超时和结构化阶段错误：连接、TLS、响应头、body idle 与总体预算；保留 errors.Is/As 因果链。当前仍是单次总超时与固定 TCP 拨号上限，不声称已经提供分阶段控制。

验收：同配置连接复用与隔离配置不串用；池满等待/取消/Close 有界释放；H2 实际协议可验证。各阶段独立超时的验收留待 2B。

## 阶段三：网络映射与 TLS 测试参数

- 显式建模逻辑 URL、拨号地址、Host 与 SNI；支持有界 resolve/connect-to、自定义 DNS 和地址族策略。
- 逻辑目标和实际地址分别执行策略；代理解析/出口边界明确，不借 Host 绕过校验。
- TLS min/max、ServerName、必要的 pinning；规定与浏览器 profile 的冲突行为。

验收：重定向重新校验、DNS rebinding、证书/SNI 不匹配、跨 origin 凭据清理与代理解析均有负向测试。

## 阶段四：流式上传、会话与认证

- reader 型上传及流式 multipart：长度、关闭、取消、重放与请求证据上限。
- 可注入/清空的内存会话，保留按 host 隔离模式与有界生命周期。
- 可选重试策略与逐次观察、退避和总预算；已交付流式正文后不透明重试。
- 按实际需求增加 Digest 和认证扩展点；挑战轮数、body replay、origin 与敏感信息脱敏明确。
- 完善普通请求规范化与 Raw 字节保真契约，不为 Raw 放宽常规安全适配。

## 阶段五：按需求扩展

WebSocket 独立模块、HTTP/3、h2c、HTTP/1.0、字节限速/low-speed、Unix socket、网卡/本地端口、企业认证和高级代理。自动续传、Cookie/ETag 文件及下载命名不是核心优先项。

## 维护方式

本计划仅定义分阶段范围，不代表后续阶段已经实现。每阶段先确定 API/安全模型，再实现运行时、测试、文档和适配字段；不以新增枚举或解析成功代替端到端能力验收。当前支持情况以 [API 与配置](API.md) 为准。
