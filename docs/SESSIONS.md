# 有界内存 Cookie 会话

默认请求仍无状态：`Config.CookieJar=false` 且 `Config.Session=nil` 时不保存或发送会话 Cookie。Raw 原始字节请求不参与 Cookie 管理，显式 `Cookie` 请求头仍属于调用方请求内容。

## 开启、注入与共享

旧的 `Config.CookieJar=true` 仍可用，现在为该 Engine 建立独立、采用默认上限的内存 Session。需要清理、预先注入 Cookie 或跨 Engine 共享时，显式构造 Session：

```go
session, err := netloom.NewSession(netloom.SessionConfig{
    MaxHosts:          128,
    MaxCookiesPerHost: 32,
    IdleTimeout:       10 * time.Minute,
})
if err != nil {
    return err
}
engine, err := netloom.New(netloom.Config{Session: session})
```

非 nil `Config.Session` 即启用 Cookie，不要求同时设置 CookieJar；同时设置时注入的 Session 优先，不另外建立私有会话。多个 Engine 可以持有同一个 Session。Engine.Close 不清理调用方拥有的 Session，也不影响仍在使用它的其他 Engine。Session 零值可直接使用，首次使用默认限制；使用后不得按值复制。

Session.Cookies / SetCookies 使用 `github.com/bogdanfinn/fhttp` 的 Cookie 类型与标准 `net/url.URL`，可显式预装或读取内存 Cookie。GetAllCookies 返回按逻辑 host 分组的独立语义快照；修改快照或 Cookies 的返回值不影响 Session。GetAllCookies 中 MaxAge 是原始接受的秒数，不是剩余秒数，不能当作重新导入后保持原过期时间的持久化格式。

## 默认值、容量和 RFC 行为

| 设置 | 零值默认 | 规则 |
| --- | --- | --- |
| MaxHosts | 256 | 所有活跃 host 条目合计上限；超出时驱逐最久未使用 host 及其全部 Cookie |
| MaxCookiesPerHost | 64 | 每个 host 的 Cookie 身份上限；按最近读取/设置驱逐，保留同名不同 path Cookie |
| IdleTimeout | 30 分钟 | 最后一次有效 host 读/写后的整组空闲 TTL |

负配置被 NewSession 拒绝，不存在通过负数开启无限容量的模式。容量限制独立于 ConnectionPool.MaxClients：客户端缓存不能作为会话内存上限。Cookie 名称、值、domain、path 的保留长度合计最多 4096 字节，超限 Cookie 整条忽略而不截断；自动产生的默认 path 也受此限制。Raw、RawExpires、Unparsed 之类原始头/任意属性不保留，字段字符串复制后存储，避免小字段引用整个大输入。逻辑 host 最多 1024 字节，超过时不建立 Session 条目。

RFC jar 负责 domain/public suffix、path 匹配、Secure、Expires、Max-Age 与删除语义；请求按较长 path 优先、同 path 创建顺序发送。这里不模拟浏览器 SameSite 导航上下文。额外隔离边界是逻辑 URL 的 hostname 加**显式端口**：不同子域即使收到共同父域 Domain Cookie 也不共享；省略端口与显式 `:80`/`:443` 分开。DNS 主机名大小写归一。scheme 不是会话分区，但 Secure Cookie 不会随 HTTP 发送。网络映射、HTTP Host 或 TLS ServerName 不会替代逻辑 URL 身份。

不使用后台清理 goroutine。读写/快照时惰性驱逐 host TTL 和访问 host 的过期 Cookie；即使没有后续调用，也不会超过配置容量。请求 Cookie 读取会更新 host LRU/空闲时间，未知 host 的读取不会建立空条目或驱逐已有会话。

## 清理与在途请求

```go
session.ClearHost("service.example:8443")
session.ClearHost("https://service.example:8443/path") // 同一逻辑 host
session.Clear()
```

ClearHost 接受 hostname、host:显式端口（IPv6 端口用方括号）或绝对 HTTP(S) URL；不推断默认端口，无效输入无操作。Clear 清理全部当前数据，ClearHost 只清理对应 host；两者线程安全，每次 jar 操作与清理之间有明确的互斥顺序。

**清理不是请求取消或认证撤销屏障**：已经生成/发送的 Cookie 头不能撤回；清理后处理到的在途响应 Set-Cookie 可以重新填充新的 Session。需要彻底隔离旧在途响应时，调用方应先取消/等待相关请求结束，或后续 Engine 使用新的 Session。缓存客户端持有的是动态 facade 而非某个 host jar：Clear、host LRU 驱逐或 TTL 后，下次读写都访问当前存储，不会偷偷继续发送旧 jar。

Session 只存在调用方显式提供的进程内存中，不持久化、不自动发现文件/用户目录、不维护全局缓存，也不会自行记录 Cookie 值。

## 本地回归

```sh
go test . -run 'Test(Session|Cookie|ConnectionPoolCookie|TLSControlsPhaseCookieJar)' -count=1 -timeout=90s
go test -race . -run '^TestSession' -count=3 -timeout=90s
```

测试使用本地 HTTP/TLS 服务和受控时钟，覆盖缓冲/流式 H1/H2/严格 H2 的复用、共享 Engine、逻辑 host 隔离、Secure/path/显式端口、容量/空闲过期、清理后的缓存客户端、在途响应重新填充、并发读写/清理及快照独立性。不依赖外部 Cookie 服务，不是浏览器完整上下文或性能验收。
