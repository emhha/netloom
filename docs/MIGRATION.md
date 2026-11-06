# 安装与使用

Netloom 是独立 Go SDK，要求 Go 1.26.0+。模块路径为 `github.com/emhha/netloom`。

## 安装

在使用 Netloom 的 Go 项目中执行：

```sh
go get github.com/emhha/netloom@latest
```

该命令需要公开仓库可访问；实际可用版本以仓库中的提交和版本标签为准。需要固定版本时，将 `@latest` 替换为已发布的版本标签。

## 导入

```go
import (
    "github.com/emhha/netloom"
    "github.com/emhha/netloom/httpdata"
    "github.com/emhha/netloom/fingerprint"
)
```

根包提供网络运行时；离线分析包可以独立使用，不需要创建 Engine。网络结果转为离线证据时使用 `github.com/emhha/netloom/httpdata/netloomdata` 的显式复制接口。

## 生命周期与安全

- 创建 Engine 后由调用方负责关闭。`Send` 返回已读取并关闭的响应；`SendStream` 返回的正文必须由调用方关闭。
- 请求须显式设置 `VerifyTLS: true` 才会验证服务器证书。根包 `Config.Retries=0` 使用默认两次重试，负数禁用重试。
- 仅访问获得授权的目标；代理出口、凭据、敏感响应与私钥的访问控制由调用方负责。
- 规则、字典及 GeoIP 数据须显式提供路径，不自动下载或安装。使用外部数据前核实相应许可。

完整调用见 [快速开始](../README.md) 和 [示例](../examples/README.md)；配置与所有权见 [API 说明](API.md)，安全边界见 [安全使用](../SAFETY.md)，路径或默认值变化见 [升级说明](UPGRADING.md)。
