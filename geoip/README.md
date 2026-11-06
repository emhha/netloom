# GeoIP 与 IP 网络信息

`geoip` 提供 IPv4/IPv6 ASN、组织、国家/城市查询，以及 CDN/WAF/云厂商识别。MMDB 数据文件是调用方提供的资源，不涉及业务数据库、ORM 或资产持久化。

```go
service, err := geoip.New("/path/to/geoip-data")
if err != nil { return err }
defer service.Close()
if err := service.Init(ctx); err != nil { return err }
info, err := service.Lookup(ctx, "1.1.1.1")
```

## 本地资源

`New` 只选择目录；`Init` 只打开已有文件，不联网、不创建目录、不读取用户目录。支持以下文件的任意可用组合：

| 文件 | 作用 |
| --- | --- |
| GeoLite2-City.mmdb | 国家、城市 |
| GeoLite2-ASN.mmdb | ASN、组织 |
| GeoLite2-Country.mmdb | 无 City 国家信息时的补充 |
| sources_data.json | cdncheck 格式的 CDN/WAF/Cloud CIDR 规则 |

没有任何资源时 `Init` 返回 `ErrNoData`；已有文件损坏时返回错误并保留之前加载的读库状态。支持仅有 CDN JSON 的使用方式。未 Init 的 Lookup 使用 best-effort 行为，返回只有 IP 的结果；非法 IP、取消或关闭会返回错误。

CIDR 最长前缀优先，同长度按 WAF > CDN > Cloud。支持 IPv4/IPv6 和 /0 默认范围；同一类别/同前缀的提供者冲突按名称字典序稳定选择。没有 CIDR 命中时使用静态 ASN 提供者回退表；该表不代表实时情报。

## 显式更新

SDK 不内置下载镜像或更新时间策略。需要下载时由调用方明确传入 URL：

```go
err := service.Update(ctx, geoip.DataSource{
    Name: "sources_data.json",
    URL: callerSelectedURL,
})
```

`New` 可选 `WithHTTPClient(client)`，由调用方指定代理和 TLS 信任策略。Update 只允许上述四个资源文件名，单文件限制 200 MiB、60 秒；取消、非 200、读取失败或超限不会替换该文件。临时文件名随机，写入完成后重命名；全部下载完成后重新加载读库状态。

这是逐文件替换，不是多文件事务：后续下载/加载失败不会回滚已经完成的磁盘替换，但旧的内存读库仍可使用。业务调度、镜像选择、数据许可及数据文件备份由调用方管理。

## 生命周期

Lookup 在 MMDB 读取完成前持有读锁，避免并发 Close/reload 关闭正在读取的内存映射；Init/Update/Close 串行处理。Close 幂等，等待正在执行的查找与更新退出，关闭后调用返回 ErrClosed。

主要入口为 IPInfo、New(dataDir, ...Option)、Init(ctx)、Lookup(ctx, ip)、LookupBatch(ctx, ips) 和 Close。Init 不自动下载或检查七天过期；Update 必须传明确的 DataSource，零参数会报错。

## 依赖与验证

MMDB 使用 geoip2-golang v1.13.0 / maxminddb-golang v1.13.0；未捆绑第三方数据文件，也未复制依赖源码。

包内回归可运行 `go test ./geoip`、`go test -race ./geoip` 和 `go vet ./geoip`。实际执行结果见 [验证记录](../docs/VALIDATION.md)。生命周期与错误路径测试不证明真实 City/ASN/Country 数据内容有效；真实数据须由具备使用许可的调用方另行验收。
