# Netloom

面向网络探测与离线分析的 Go SDK：可控的网络运行时、HTTP 证据快照、指纹识别，以及可独立使用的扩展包。

Netloom 是库，不是扫描平台或常驻服务。任务编排、目标授权、凭据管理、数据持久化和界面由调用方负责。

> 要求 Go 1.26.0+，模块路径为 `github.com/emhha/netloom`。安装方式见 [安装与使用](docs/MIGRATION.md)，公开 API 变化见 [升级说明](docs/UPGRADING.md)。

## 快速开始

在 Go 项目中安装（需要公开仓库可访问）：

```sh
go get github.com/emhha/netloom@latest
```

在本仓库中可运行 `go run ./examples/request https://example.com`。最小调用：

```go
package main

import (
    "context"
    "fmt"

    "github.com/emhha/netloom"
)

func main() {
    engine, err := netloom.New(netloom.Config{Retries: -1})
    if err != nil {
        panic(err)
    }
    defer engine.Close()

    response, err := engine.Send(context.Background(), &netloom.Request{
        URL: "https://example.com", VerifyTLS: true,
    })
    if err != nil {
        panic(err)
    }
    fmt.Println(response.StatusCode)
}
```

`Send` 返回已读取并关闭的响应；`SendStream` 的调用方必须关闭 `Body`。`Engine.Close` 取消工作并等待退出。更多用法见 [示例](examples/README.md) 和 [API 与配置](docs/API.md)。

## 能力与包

| 层次 | 包 | 用途 |
| --- | --- | --- |
| 网络运行时 | 根包 `netloom` | HTTP/HTTPS、TLS 指纹、CA/mTLS、代理、Raw、流式请求、Cookie、重定向、Pipeline、调度与限流 |
| 离线证据 | `httpdata`、`httpdata/netloomdata` | 标准库快照与运行时结果的显式复制 |
| 离线分析 | `fingerprint`、`infoextract`、`passive` | 指纹、信息提取、被动分析与内置插件 |
| 主动探测 | `probe`、`dirscan` | 探活、目录扫描 |
| 网络工具 | `nethttp`、`mitm`、`geoip` | cURL 转换、MITM 原语、ASN/位置与 CDN/WAF/云识别 |
| 数据源查询 | `httpclient`、`mapping`、`enterprise` | 独立 API 会话、测绘服务与企业信息适配 |

包依赖方向和目录职责见 [架构](docs/architecture.md)；各包的能力限制由 [文档索引](docs/README.md) 导航。

## 使用前注意

完整边界见 [安全使用说明](SAFETY.md)。

- 根包 TLS 验证须显式设置 `VerifyTLS: true`。`Retries=0` 表示默认重试两次，负数才禁用；不要把不同客户端的默认值混用。
- 直接拨号拒绝回环、未指定和链路本地地址，允许私网；代理出口策略由代理负责。这不是完整的 SSRF 防护，调用方仍须校验目标授权。
- [指纹规则](fingerprint/rules/README.md) 和 [目录字典](dirscan/wordlists/README.md) 必须显式配置，不自动读取用户目录或 embed 到二进制。规则匹配只分析已有证据，不主动发送探针。
- MITM 不自动监听或安装证书；私钥保管归调用方。[GeoIP](geoip/README.md) 初始化只读指定本地资源，下载须显式提供 URL。
- 数据源 API 可能收费或受频率限制；凭据、调用权限和付费重试策略由调用方选择，见各包说明。

## 开发与验证

```sh
make check        # 格式、仓库/文档检查、单元测试、vet、构建
make race         # Go race 测试
make integration-compile  # 只编译集成测试，不执行外部请求
```

需要 Go、Python 3、Git 和 Make；不用 Make 时的等价命令见 [开发指南](docs/development.md)。测试分类见 [测试说明](docs/testing.md)，实际执行结果与历史环境限制见 [验证记录](docs/VALIDATION.md)。

## 文档与许可

- [文档索引](docs/README.md)：架构、配置、开发、测试与迁移。
- [贡献指南](CONTRIBUTING.md)：变更约定和提交前检查。
- [来源与许可](docs/SOURCES.md)：第三方来源、资源许可与发布限制。

保留适用的 [AGPL-3.0 许可文本](LICENSE)。部分实现和第三方规则的再分发权利尚待核实；公开发布前须完成许可审查。项目名称与模块路径不改变第三方许可义务。
