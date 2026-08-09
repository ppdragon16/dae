# dae-ppdn

**中文** | [**English**](README.md)

**_dae-ppdn_** 是 [dae-next](https://github.com/LostAttractor/dae) 的个人分支，根据作者的实际使用体验和需求不断添加功能并优化性能。

与上游 dae 一样，它是一个基于 eBPF 的高性能透明代理方案，利用 Linux 内核进行流量分流——直连流量完全绕过代理进程，实现接近零损耗的转发。

## 项目谱系

```
dae (daeuniverse/dae)          — 原始项目
 └─ dae-next (LostAttractor/dae) — 重构 outbound 接口，新增配置项
      └─ dae-ppdn (本项目)       — HTTP APIs、DNS 增强、扩展协议支持
```

### dae-next vs dae

| 类别 | 变更 |
|---|---|
| `dial_mode` 替代 | 拆分为三个独立配置项：`dial_target_override`、`reroute_mode`、`sniff_verify_mode` |
| Group `priority` | Group 中的节点可定义 `priority`，支持权重、顺序和延迟参数（如 `priority: '0,2(,300ms)'`） |
| `min_moving_avg` EMA 参数 | `min_moving_avg` 策略支持可配置的 EMA 算法参数：`min_moving_avg(window, alpha)`（如 `min_moving_avg(10s, 0.2)`） |
| Metrics | 重构了内部指标 |
| Outbound 接口 | 重构——各协议需重新适配（进度见 [LostAttractor/dae](https://github.com/LostAttractor/dae)） |

**配置兼容性：** dae-ppdn 兼容 dae-next 配置。dae-next **不**兼容 dae 配置。

### dae-ppdn vs dae-next

| 类别 | 新增内容 |
|---|---|
| HTTP APIs | 通过 `command_port` 提供 RESTful 命令接口（redirect 控制、priority 管理、动态 DNS 静态条目） |
| `udp_sniff_ports` | 可配置的 UDP 流量嗅探端口列表（默认 `443`） |
| DNS `dns_cache_tag` | 节点级 DNS 缓存域标注（`-l`），同 VPS/地区的节点可共享 DNS 缓存 |
| DNS `static` | 用户自定义静态 DNS 条目，支持 A、AAAA、TXT 记录，可通过 HTTP API 热更新 |
| DNS `via` | DNS 查询通过指定 outbound 组发出（如 `proxy_dns(via: ai)`） |
| DNS `race` | 并发查询多个上游，取最快响应 |
| DNS `mac` + `sip` | 基于 MAC 地址或源 IP 的客户端级 DNS 过滤 |
| DNS pool 调优 | 可配置 `udp_pool_size`、`udp_pool_ttl`、`tcp_pool_size`、`tcp_pool_ttl` |
| 协议 | 扩展支持：Trojan、SSR、SS、SS2022、VLESS、VMess、AnyTLS、Tuic (v5)、Juicity、Hysteria2 |
| VLESS mux | 同时支持 v2ray 原生 mux 和 sing-box smux |

> **注意：** 部分协议参数可能支持不全，具体请参阅源码。

部分性能优化参考了 [kdae](https://github.com/olicesx/dae/tree/kdae) 的代码。例如 eBPF maps 使用 `BPF_MAP_TYPE_HASH` 而非 `BPF_MAP_TYPE_LRU_HASH`——内核不会静默淘汰条目，避免了内核态与用户态的状态不一致。取而代之的是用户态 **Janitor**（`control/bpf_map_janitor.go`），定期扫描并根据各 map 类型的超时设置显式清理过期条目。

## Node Priority

Group 中的每个节点可以通过 `filter` 行中的 `priority` 标注来控制节点选择的相对权重：

```shell
group {
  hk {
    filter: subtag(sub1) && name(regex:'香港') [priority: '0,2(,300ms)']
    filter: subtag(sub2) && name(regex:'香港') [priority: '0,1(,200ms)']
    filter: subtag(sub3) && name(regex:'香港')
    policy: min_moving_avg
  }
}
```

`priority` 值由一个**默认优先级**和可选的**条件优先级**（基于实测延迟）组成：

```
priority: '<default>[,<pri>(<latency_low>,<latency_high>)[; ...]]'
```

| 部分 | 含义 |
|---|---|
| `<default>` | 基础优先级，当没有延迟条件匹配时使用 |
| `<pri>(<low>,<high>)` | 当节点实测延迟落在 `[low, high]` 范围内时，覆盖为基础优先级 |

在上面的例子中：
- `sub1` 节点默认优先级为 0，但当延迟低于 300ms 时跳到优先级 **2**——配合 `min_moving_avg` 策略，更高优先级的节点会被优先选择，因此 sub1 在速度好时占据主导。
- `sub2` 节点默认优先级为 0，当延迟低于 200ms 时跳到优先级 **1**——更严格的延迟门槛但更低的激励。
- `sub3` 节点没有标注，优先级始终为 0，无条件提升。

这种机制实现了精细的流量调度：在质量较好的时段让优质节点承担更多流量，而不会永久性地冷落其他节点。

## Outbound Redirect

Outbound redirect 允许一个 group 将所有流量透明转发到另一个 group。Redirect group 自身没有节点、过滤器或策略——它只是一个轻量级别名。

Redirect 在**两个层面**生效：

- **配置层面** — 在 `group` 块中声明 `redirect: <target>`，所有路由到源 group 的流量通过 direct dialer 转发到目标 group。
- **运行时层面** — 通过 [HTTP API](#redirect-管理) 动态修改 redirect 目标，无需重载配置。

```shell
group {
  # 这些 group 将流量转发到对应地区的 group
  macbook {
    redirect: tw
  }
  wg {
    redirect: hk
  }
  ai {
    redirect: sg
  }

  # 具有节点和策略的实际 group
  hk {
    filter: subtag(sub1) && name(regex:'香港')
    policy: min_moving_avg(10s, 0.2)
  }
  tw {
    filter: subtag(sub1) && name(regex:'台湾')
    policy: min_moving_avg(10s, 0.2)
  }
  sg {
    filter: subtag(sub1) && name(regex:'新加坡')
    policy: min_moving_avg(10s, 0.2)
  }
}

routing {
  # 将特定设备/流量路由到 redirect group
  mac('11:22:33:44:55:66') -> macbook
  sip(10.0.0.1/24) -> wg
  domain(keyword:gemini, keyword:openai) -> ai
  fallback: hk
}
```

Redirect group 零开销：不携带节点、跳过连通性检查；当 redirect 目标是 `direct` 或 `block` 时，流量完全在 eBPF 内核空间短路处理，不经过用户态。

## Hot Config Update

`dae update` 支持**不中断现有连接**地热更新配置的特定部分——重新读取配置文件并仅应用变更的部分。

```bash
dae update sub     # 重新拉取订阅，刷新节点列表
dae update dns     # 应用 DNS 配置变更（上游、路由规则）
dae update routing # 应用路由规则变更
```

### `dae update sub`

订阅更新会重新解析所有订阅并热替换节点，但 group 的**结构**必须保持不变——结构变更需要通过完整重载（`SIGUSR1`）：

| 允许 | 不允许（需 SIGUSR1 完整重载） |
|---|---|
| 通过订阅增删节点 | 新增或删除 `group` 块 |
| 修改 `filter` 规则和标注 | 重命名 group |
| 修改 `policy` 参数 | 改变 group 数量 |
| 修改节点 priority / latency 参数 | 将 group 在 redirect 和普通模式间切换 |
| 修改 redirect 目标（`redirect: x` → `redirect: y`） | |
| 增删 subscription 块 | |

> **注意：** 同一时间只能执行一个 `dae update` 命令——并发更新会被静默跳过。

### `dae update dns`

热替换整个 DNS 子系统（上游、路由规则、缓存设置）。如果 `via` 引用了不存在的 group，命令会失败。

### `dae update routing`

热替换路由规则表。如果路由规则引用了不存在的 group（outbound），命令会失败。

## HTTP APIs

在全局配置中设置 `command_port` 后，dae-ppdn 会暴露 RESTful HTTP 接口：

### Redirect 管理

```bash
# 列出所有 outbound 及其 redirect 目标
curl http://localhost:1111/redirect

# 将某个 outbound 重定向到其他 group
curl -X PUT http://localhost:1111/redirect/fb \
  -H "Content-Type: text/plain" -d 'tw'

# 移除 redirect（指向自身）
curl -X PUT http://localhost:1111/redirect/fb \
  -H "Content-Type: text/plain" -d 'fb'
```

### Priority 管理

```bash
# 列出所有优先级
curl http://localhost:1111/priority

# 修改特定节点的优先级（通过 query params）
curl -X PUT "http://localhost:1111/priority?outbound=hk&subtag=sub3&dialer=香港" \
  -H "Content-Type: text/plain" -d '0,3(,300ms)'
```

> 结合 redirect 和 priority API 可以实现**手动切换节点**：将某个 group redirect 到单节点 group，或将特定节点的 priority 提升到最大值以强制流量走该节点。

### 反向 IP 查询

```bash
# 查询某个 IP 曾被哪些域名解析
curl http://localhost:1111/lookup/1.2.3.4
```

### 静态 DNS 管理

在 `dns.static` 中定义的静态 DNS 条目可在运行时更新，无需重启：

```bash
# 列出所有静态条目
curl http://localhost:1111/static

# 获取特定条目
curl http://localhost:1111/static/local_nas

# 更新条目（多字段）
curl -X PUT http://localhost:1111/static/local_nas \
  -H "Content-Type: text/plain" \
  -d $'a: 192.168.16.42\naaaa: fdfe::be24:11ff:fe64:1234\nttl: 3600'
```

> 静态 DNS 响应**不被缓存**，因此更新即时生效。

## DNS Enhancements

### `dns_cache_tag`（`-l` 标注）

共享相同 `-l` 标签的节点使用共享的 DNS 缓存域。当多个节点位于同一 VPS 的同一地区时，它们可以安全地共享缓存的 DNS 结果，减少上游查询：

```shell
group {
  mix {
    filter: subtag(sub1) && name(keyword:'新加坡') [dns_cache_tag: 'sg']
    filter: subtag(sub2) && name(keyword:'东京')   [dns_cache_tag: 'jp']
    policy: min_moving_avg
  }
}
```

### `dns/static`

在配置中直接定义静态 A、AAAA 和 TXT 记录，然后在 DNS 路由中通过 `static(name)` 引用：

```shell
dns {
  static {
    local_nas {
      a: 192.168.16.42
      aaaa: 'fdfe::be24:11ff:fe64:3598'
      ttl: 600
    }
  }
  routing {
    request {
      qname(suffix:mydomain.xyz) -> static(local_nas)
    }
  }
}
```

### `dns/via`

强制 DNS 上游查询使用指定的 outbound group：

```shell
qname(keyword:gemini, keyword:openai) -> proxy_dns(via: ai)
```

### `dns/race`

并发查询多个上游，使用最先返回的响应：

```shell
qname(geosite:gfw) -> race(proxy_dns, googledns)
```

### `dns/mac` + `dns/sip`

基于 MAC 地址或源 IP 的客户端级 DNS 过滤：

```shell
qtype(aaaa) && mac('11:22:33:44:55:66') -> reject
qtype(aaaa) && sip(192.168.1.100) -> reject
```

### DNS Pool 调优

控制每个 DNS 转发器的连接池行为（按 upstream + dialer + target 分组）：

```shell
dns {
  udp_pool_size: 10     # 每个转发器的 UDP 连接数
  udp_pool_ttl: 10m     # 空闲 UDP 连接回收 TTL
  tcp_pool_size: 2      # 每个转发器的 TCP 连接数
  tcp_pool_ttl: 30s     # 空闲 TCP 连接回收 TTL
}
```

## 支持的协议

| 协议 | Schemes | 备注 |
|---|---|---|
| HTTP(S) | `http`、`https` | 通用 HTTP CONNECT 代理 |
| Socks5 | `socks`、`socks5` | |
| Shadowsocks | `ss`、`shadowsocks` | AEAD、stream ciphers、SS2022（`2022-blake3-aes-*`）、simple-obfs、v2ray-plugin (WS+TLS) |
| ShadowsocksR | `ssr`、`shadowsocksr` | |
| VMess | `vmess` | AEAD, alterID=0；TCP、WS、TLS、gRPC、Meek、HTTPUpgrade |
| VLESS | `vless` | Reality、gRPC、Meek、HTTPUpgrade、mux、smux |
| Trojan | `trojan`、`trojan-go` | trojan-gfw 和 trojan-go |
| Tuic | `tuic` | v5 |
| Juicity | `juicity` | |
| Hysteria2 | `hysteria2`、`hy2` | |
| AnyTLS | `anytls` | |
| Proxy chain | `->` | 用 `->` 分隔符串联多个协议 |

详见 [docs/en/proxy-protocols.md](./docs/en/proxy-protocols.md)。

### VLESS Mux & SMux

VLESS 同时支持 v2ray 原生 mux 和 sing-box smux 连接多路复用。在 VLESS 节点链接中添加以下 query 参数：

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `mux` / `multiplex` | bool | `false` | 启用 v2ray 原生 mux |
| `smux` | bool | `false` | 启用 sing-box smux |
| `mux_concurrency` | int | `8` | 每条连接的最大并发流数 |
| `mux_idle_timeout` | int | `300` | 子连接的空闲超时（秒），超时后关闭 |

> **注意：** `mux` 和 `smux` 与 `flow` 不兼容（例如 `xtls-rprx-vision`）。

示例：

```
vless://uuid@host:port?type=tcp&security=reality&smux=1&mux_concurrency=4&mux_idle_timeout=120#节点名称
```

### AnyTLS Idle Session

AnyTLS 支持维护空闲会话池，避免每次发起连接时的握手开销。通过 URL query 参数配置：

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `minIdleSession` | int | `0` | 保持的最小空闲会话数，新增连接可直接复用 |
| `idleCheckInterval` | duration | — | 扫描过期空闲会话的间隔（如 `30s`） |
| `idleTimeout` | duration | — | 空闲会话的最大存活时间（如 `5m`），超时后回收 |

示例：

```
anytls://user@host:port?minIdleSession=2&idleCheckInterval=30s&idleTimeout=5m#节点名称
```

## 快速开始

请参阅[快速开始指南](./docs/zh/README.md)了解内核要求、安装方式和最小配置。

完整示例配置见 [example_next.dae](./example_next.dae)。

## License

[AGPL-3.0 (C) daeuniverse](https://github.com/daeuniverse/dae/blob/main/LICENSE)

## 致谢

- 原始项目 [dae](https://github.com/daeuniverse/dae)（daeuniverse）
- [dae-next](https://github.com/LostAttractor/dae)（LostAttractor）
- 所有[贡献者](https://github.com/daeuniverse/dae/graphs/contributors)
