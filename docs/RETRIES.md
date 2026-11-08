# 重试策略与逐次观察

根包保持原有 `Config.Retries` 数值默认：0 补2，负值禁用。未配置新策略时仅对 GET/HEAD/OPTIONS 的网络错误重试；Send 和 Run 使用同一规则，Raw 不重试。HTTP 错误状态默认仍不重试。

`Config.RetryPolicy *RetryPolicy` 提供可选 engine 策略，`Request.RetryPolicy` 非 nil 时整组覆盖。nil 继承；非 nil 零对象禁用重试。配置由 New 和发送路径复制；回调捕获对象仍属调用方，调用期间不要并发修改输入。

```go
policy := &netloom.RetryPolicy{
    MaxRetries: 2, // 初次发送以外的次数
    StatusCodes: []int{429, 503},
    BaseDelay: 100 * time.Millisecond,
    MaxDelay: 2 * time.Second,
    RespectRetryAfter: true,
    Observer: func(a netloom.AttemptInfo) {
        // 非阻塞、线程安全；不在此处同步 Close 所属 Engine。
    },
}
```

- Methods=nil 只允许 GET/HEAD/OPTIONS；显式空数组不允许任何方法。显式加入 PUT/DELETE/POST 等表示调用方确认副作用和幂等性；SDK 不生成幂等键，也不承诺服务端没有收到失败尝试。
- bytes 正文可重放；Upload 只有通过 replayable opener 明确声明才可重放。不满足条件时只发送一次，不先消耗 one-shot reader 再失败重试。Raw 完全不参与重试，避免重复执行多请求字节串。
- MaxRetries 有界0..100，methods/status 列表有界且校验；状态只接受400..599。网络错误与选中状态可触发重试；受阻地址、pin、TLS配置冲突、证书验证错误、认证协议/配置、无效/不支持/运行期失败的本地绑定（`ErrNetworkBindingInvalid` / `ErrNetworkBindingUnsupported` / `ErrNetworkBinding`）和正文不可重放/短读错误不重试。调用方取消与 Total 立即终止。
- BaseDelay 确定性指数增长，不含 jitter；MaxDelay 为0时上限30秒，最大允许1分钟，BaseDelay 不能超过显式上限。BaseDelay 为0无固定等待。Retry-After 支持非负秒数和 HTTP-date，作为最低建议但**仍裁剪到 MaxDelay**；无效或过去日期不增加等待。
- 每次重试前等待可被 context、Engine.Close 和外层 Total 中断。单次 Request.Timeout 不覆盖两次尝试之间的退避；PhaseTimeouts.Total 覆盖全部尝试/退避，Do 的外层 Total 也覆盖跳转及其内部重试。
- 选中状态在重试前已按 MaxBodySize 读取/关闭并释放租约；不自动交付中间响应流。后续尝试在 headers 前失败时仍保留最近一次非 nil Response，故 Response 和最终 error 可能来自不同尝试。最终选中状态没有传输错误时仍返回正常 Response，不把429/503变成网络错误。

## Observer

Observer 每次完成 transport 尝试后同步调用，Attempt 从1开始，包含方法、状态、错误、耗时、是否计划继续和等待时间。Duration 不含之后的等待，不提供 URL、请求头或正文。WillRetry 是当时的决策，不保证下一次必然发生：观察后取消/Total 到期仍能终止等待。认证挑战属于同一 transport 尝试，不单独计数。SDK 禁用 fhttp 的隐式 GetBody 重开，重放由上述显式策略管理；底层未发送应用数据的协议/建连内部重连不作为独立应用 attempt。

SendStream 从不自动重试，包括配置的状态码；Observer 仅报告交付响应头前的一次尝试，WillRetry=false，不为后续应用读取错误再次发送。终态正文信息通过 StreamResponse.Status 获取。预检/准入失败尚未形成 transport 尝试时不会调用 Observer。

## 结构化输入

`nethttp.RequestInput.Retry` 对应 JSON `retry`：max_retries、methods、status_codes、base_delay_ms、max_delay_ms、respect_retry_after，使用有界整数毫秒，不支持 JSON 函数。缺失/null 继承，空对象禁用。新增输入不改变 ParseCurl 的命令行兼容范围。
