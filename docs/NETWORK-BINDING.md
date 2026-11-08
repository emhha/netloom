# 按请求绑定源 IP 与网络接口

`netloom.Request.Network` 的 `LocalAddress` 和 `Interface` 控制新建 TCP socket 的本地绑定，适用于根包指纹传输的普通请求、流式请求和 Raw 请求。它们不是 HTTP 头、TLS 指纹或逻辑目标替换功能，也不会修改系统路由、接口配置或持久状态。

配置仅属于单次请求：没有 `Config` 级默认绑定，不从环境自动选择设备，不提供源端口选择。零值保持原有行为；源端口由操作系统分配。已有的 `Resolve`、`ConnectTo` 和 `AddressFamily` 可以与绑定组合，详细映射行为见 [API 与配置](API.md)。

## Go 示例

以下地址和接口名仅作语法示例；实际执行前，调用方必须选择本机已配置且具有目标路由的源 IP 和接口。文档专用 IP 并不意味着可在本机成功绑定或访问外网。

```go
package main

import (
    "context"
    "log"

    "github.com/emhha/netloom"
)

func main() {
    engine, err := netloom.New(netloom.Config{})
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    request := &netloom.Request{
        Method:    "GET",
        URL:       "https://example.com/",
        VerifyTLS: true,
        Network: &netloom.NetworkOptions{
            LocalAddress: "192.0.2.10", // 换成本机已配置的单播 IP
            Interface:    "eth0",       // 仅 Linux；换成所需接口名
        },
    }
    response, err := engine.Send(context.Background(), request)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("status=%d", response.StatusCode)
}
```

只需绑定源 IP 时可省略 `Interface`，此时出口设备仍由操作系统路由决定。只需约束设备时可省略 `LocalAddress`，此时源 IP 由操作系统根据该设备和目标选择。两者同时设置时必须同时满足；SDK 不替调用方纠正不匹配的配置。

## JSON 输入

`nethttp.RequestInput.network` 直接使用根包的 `NetworkOptions`，由 `nethttp.BuildRequest` 做同样的验证并复制：

```json
{
  "url": "https://example.com/",
  "method": "GET",
  "network": {
    "local_address": "192.0.2.10",
    "interface": "eth0",
    "address_family": "ipv4"
  }
}
```

省略 `network` 或传入 `null` 得到 nil 策略；`{}` 保留非 nil 零值策略，但不启用绑定。`local_address` 和 `interface` 的空字符串表示未配置。构建请求和原生 `NetworkOptions.Clone` 不改变调用方对象，返回的策略及映射切片独立于输入。语法验证不执行 DNS、接口存在性查询或连接探测；Linux 上名称语法正确不保证设备存在、地址已配置或当前进程有绑定权限。

## 源 IP 与地址族

- `LocalAddress` 必须是明确、不含 zone 的单播 IP literal，不能是主机名、URL、带端口地址或带方括号的 IPv6 地址。
- 未指定地址 `0.0.0.0`、`::`、组播及有限广播地址 `255.255.255.255` 无效。IPv4-mapped IPv6 会在内部规范化为 IPv4，包括 `::ffff:192.0.2.10`；不会原地改写调用方字符串。
- 源 IP 隐式约束目标地址族：IPv4 源仅连接 IPv4，IPv6 源仅连接 IPv6。显式 `AddressFamily` 与源冲突属于无效配置；`auto` 也不允许跨源地址族回退。
- IPv6 依赖本机 IPv6 地址、路由和目标可达性。不能用 `fe80::1%eth0` 指定带 zone 的源地址；设置 `Interface` 也不使这种语法有效。不承诺为链路本地 IPv6 目标自动补 zone。
- 选择本地源 IP 不保证对端看到该地址。NAT、网关、隧道或其他网络设施可能改写公网出口地址；它不是“指定外部 NAT IP”的接口。

## Linux 接口绑定与权限

`Interface` 在 Linux 上通过 `SO_BINDTODEVICE` 作用于实际新建的 TCP socket。接口名按字节计长，必须为 1–15 字节可打印 ASCII，不含空白、`/` 或 `:`，且不能为 `.` 或 `..`。空字符串表示不绑定设备。接口名区分大小写，不接受接口 IP 或接口索引作为替代语法。

此能力可能需要 Linux capability（例如 `CAP_NET_RAW`），具体取决于内核、容器、用户命名空间和安全策略。调用方自行管理最小权限；SDK 不自动提权、不修改 capability、不换另一设备，也不会在失败后退回未绑定连接。

非 Linux 平台不支持非空 `Interface`，`NetworkOptions.Validate` 和 `nethttp.BuildRequest` 即返回可用 `errors.Is` 检查的 `ErrNetworkBindingUnsupported`。仅源 IP 绑定不受这一平台限制。

错误分类：

| 错误 | 含义 |
| --- | --- |
| `ErrNetworkBindingInvalid` | 源 IP、接口名或源地址族组合无效；验证错误保留该 sentinel |
| `ErrNetworkBindingUnsupported` | 当前平台不支持所请求的接口绑定 |
| `ErrNetworkBinding` | 实际绑定失败；保留底层权限、设备等系统错误，源地址不可用的 `EADDRNOTAVAIL` 也归此类 |
| `ErrNetworkProxyUnsupported` | 非零网络策略与代理同时使用 |

使用 `errors.Is(err, netloom.ErrNetworkBinding)` 判断运行期绑定失败，也可继续用 `errors.Is` / `errors.As` 检查包装的系统原因。这些绑定错误均不参与自动重试；内核拒绝绑定时不会继续尝试其他目标候选或未绑定连接。SDK 不把权限或设备错误悄悄降级为成功；诊断时应核查源 IP 是否已配置、接口是否存在及进程权限，而不是依赖未绑定重试。

## 直连边界、DNS 与目标保护

任何非零 `Network` 策略（包括仅设置源 IP 或接口）均为直连专用。与任何代理组合返回 `ErrNetworkProxyUnsupported`，不会将绑定偷偷应用到代理连接，也不推测代理端 DNS、出口或地址族语义。此约束不因普通、流式或 Raw 路径不同而放宽。

绑定作用于到有效目标的 TCP socket，**不绑定 DNS resolver 自身的 UDP/TCP 流量**。源 IP 会筛选 DNS 返回的目标地址族，但不能保证 DNS 查询经指定接口发出；需要控制 DNS 出口时，由调用方在 SDK 外配置明确的 resolver/网络环境。使用匹配的 `Resolve` 规则可避免该目标的 DNS 查询，但不会修改系统解析器或路由。

逻辑 URL、HTTP Host、TLS SNI 与证书验证身份不因绑定改变。`Do` 重定向保留网络策略并为后续请求复制，不修改调用方请求；逐跳目标与拨号保护仍有效。绑定本地源地址或 loopback 接口不授予访问 loopback 等受阻目标的权限。测试中的私有 `noGuard` 路径仅用于受控本机回归，不是公共绕过配置。

## 连接池与接口生命周期

连接池身份包含规范化后的完整网络策略：源 IP、接口名、地址族及映射均参与隔离。等价的 IPv4 与 IPv4-mapped 源地址按规范化身份处理；不同策略不会通过池复用偷用另一种绑定。

绑定是 **connect-time** 属性。复用已有 socket 时不会重新执行接口绑定或检查当前路由。接口名在新连接时由 Linux 解析；接口之后重命名、删除或以同名重建，不会触发 SDK 对已有 socket 的重新验证或重新绑定。已有连接的实际存活和后续行为仍由内核网络状态决定。

SDK 不监控网络变化，不自动迁移连接。需要重新建立 socket 时显式设置 `Request.FreshConnection`（JSON 为 `fresh_connection`），或关闭旧 Engine 并创建新的 Engine；这不能保证故障路由或权限自动恢复。流式响应仍须关闭响应体，连接池与 Engine 的常规生命周期责任不变。完整连接与重定向约束见 [API 与配置](API.md)，本地回归操作见 [测试说明](testing.md)。
