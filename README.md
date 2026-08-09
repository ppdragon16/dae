# dae-ppdn

[**中文**](README.zh.md) | **English**

**_dae-ppdn_** is a personal fork of [dae-next](https://github.com/LostAttractor/dae), continuously enhanced with features and performance optimizations based on the author's real-world usage and needs.

Like upstream dae, it is a high-performance transparent proxy solution that leverages eBPF in the Linux kernel for traffic splitting — direct traffic bypasses the proxy entirely, achieving near-zero performance overhead.

## Project Lineage

```
dae (daeuniverse/dae)          — Original project
 └─ dae-next (LostAttractor/dae) — Refactored outbound interface, new config options
      └─ dae-ppdn (this repo)    — HTTP APIs, DNS enhancements, extended protocol support
```

### dae-next vs dae

| Category | Change |
|---|---|
| `dial_mode` replacement | Replaced with three independent config options: `dial_target_override`, `reroute_mode`, `sniff_verify_mode` |
| Group `priority` | Nodes in a group can now define a `priority` with weight, order, and latency parameters (e.g. `priority: '0,2(,300ms)'`) |
| `min_moving_avg` EMA params | The `min_moving_avg` policy now supports configurable EMA algorithm parameters: `min_moving_avg(window, alpha)` (e.g. `min_moving_avg(10s, 0.2)`) |
| Metrics | Restructured internal metrics |
| Outbound interface | Refactored — all protocols require re-adaptation (progress tracked at [LostAttractor/dae](https://github.com/LostAttractor/dae)) |

**Config compatibility:** dae-ppdn is compatible with dae-next configs. dae-next is **not** compatible with dae configs.

### dae-ppdn vs dae-next

| Category | Additions |
|---|---|
| HTTP APIs | RESTful command server via `command_port` (redirect control, priority management, dynamic DNS static entries) |
| `udp_sniff_ports` | Configurable UDP port list for traffic sniffing (default: `443`) |
| DNS `dns_cache_tag` | Dialer-level DNS cache domain annotation (`-l`), allowing dialers on the same VPS/region to share DNS cache |
| DNS `static` | User-defined static DNS entries with A, AAAA, TXT records — hot-reloadable via HTTP API |
| DNS `via` | Route DNS queries through a specific outbound group (e.g. `proxy_dns(via: ai)`) |
| DNS `race` | Query multiple upstreams concurrently, first response wins |
| DNS `mac` + `sip` | Per-client DNS filtering by MAC address or source IP |
| DNS pool tuning | Configurable `udp_pool_size`, `udp_pool_ttl`, `tcp_pool_size`, `tcp_pool_ttl` |
| Protocols | Extended support: Trojan, SSR, SS, SS2022, VLESS, VMess, AnyTLS, Tuic (v5), Juicity, Hysteria2 |
| VLESS mux | Supports both v2ray-native mux and sing-box smux |

> **Note:** Some protocol parameters may have incomplete support. Refer to the source for specifics.

Some performance optimizations are inspired by [kdae](https://github.com/olicesx/dae/tree/kdae). Notably, eBPF maps use `BPF_MAP_TYPE_HASH` instead of `BPF_MAP_TYPE_LRU_HASH` — the kernel never silently evicts entries, avoiding state inconsistency between kernel and userspace. Instead, a userspace **Janitor** (`control/bpf_map_janitor.go`) periodically scans and cleans up stale entries with explicit timeouts per map type.

## Node Priority

Each node in a group can carry a `priority` annotation in the `filter` line, controlling its relative weight in node selection:

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

The `priority` value consists of a **default priority** and optional **conditional priorities** based on observed latency:

```
priority: '<default>[,<pri>(<latency_low>,<latency_high>)[; ...]]'
```

| Part | Meaning |
|---|---|
| `<default>` | Base priority used when no latency condition matches |
| `<pri>(<low>,<high>)` | Override priority when the node's observed latency falls within `[low, high]` |

In the example above:
- `sub1` nodes default to priority 0, but jump to priority **2** when latency is below 300ms — with a `min_moving_avg` policy, higher-priority nodes are preferred, so sub1 dominates when it's fast.
- `sub2` nodes default to priority 0, jump to priority **1** when below 200ms — a tighter latency requirement with lower reward.
- `sub3` nodes have no annotation, meaning priority defaults to 0 with no conditional boost.

This mechanism allows fine-grained traffic steering: give higher-quality nodes more traffic during good periods, without permanently de-prioritizing other nodes.

## Outbound Redirect

Outbound redirect allows one group to transparently forward all traffic to another group. A redirect group has no nodes, filters, or policies of its own — it acts as a lightweight alias.

Redirect is resolved at **two levels**:

- **Config level** — declare `redirect: <target>` in a `group` block. All traffic routed to the source group is forwarded to the target group via a direct dialer.
- **Runtime level** — change redirect targets on the fly via the [HTTP API](#redirect-management), no config reload required.

```shell
group {
  # These groups forward traffic to region-specific groups
  macbook {
    redirect: tw
  }
  wg {
    redirect: hk
  }
  ai {
    redirect: sg
  }

  # Real groups with nodes and policies
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
  # Route specific devices/traffic to the redirect groups
  mac('11:22:33:44:55:66') -> macbook
  sip(10.0.0.1/24) -> wg
  domain(keyword:gemini, keyword:openai) -> ai
  fallback: hk
}
```

Redirect groups are zero-cost: they carry no nodes, skip connectivity checks, and when redirected to `direct` or `block`, traffic is short-circuited entirely in eBPF kernel space without touching userspace.

## Hot Config Update

`dae update` allows hot-updating specific parts of the running configuration **without a full reload** — existing connections are not interrupted. It works by re-reading the config file and applying only the changed sections.

```bash
dae update sub     # Re-fetch subscriptions, refresh node list
dae update dns     # Apply DNS config changes (upstreams, routing rules)
dae update routing # Apply routing rule changes
```

### `dae update sub`

Subscription update re-resolves all subscriptions and hot-swaps dialers, but the overall group **structure** must be preserved — structural changes require a full reload (`SIGUSR1`):

| Allowed | Rejected (use SIGUSR1 for full reload) |
|---|---|
| Add/remove nodes via subscription | Add or delete a `group` block |
| Modify `filter` rules and annotations | Rename a group |
| Change `policy` parameters | Change group count |
| Change node priority / latency params | Switch a group between redirect and normal |
| Modify redirect target (`redirect: x` → `redirect: y`) | |
| Add/remove subscription blocks | |

> **Note:** Only one `dae update` command can run at a time — concurrent updates are silently skipped.

### `dae update dns`

Hot-swaps the entire DNS subsystem (upstreams, routing, cache settings). The command will fail if a `via` target references a group that does not exist.

### `dae update routing`

Hot-swaps the routing rule table. The command will fail if a routing rule references a group (outbound) that does not exist.

## HTTP APIs

When `command_port` is set in the global config, dae-ppdn exposes RESTful HTTP endpoints:

### Redirect Management

```bash
# List all outbounds with redirect targets
curl http://localhost:1111/redirect

# Redirect an outbound to a different group
curl -X PUT http://localhost:1111/redirect/fb \
  -H "Content-Type: text/plain" -d 'tw'

# Remove a redirect (point back to itself)
curl -X PUT http://localhost:1111/redirect/fb \
  -H "Content-Type: text/plain" -d 'fb'
```

### Priority Management

```bash
# List all priorities
curl http://localhost:1111/priority

# Change a specific dialer's priority (via query params)
curl -X PUT "http://localhost:1111/priority?outbound=hk&subtag=sub3&dialer=香港" \
  -H "Content-Type: text/plain" -d '0,3(,300ms)'
```

> Combining redirect and priority APIs enables **manual node switching**: redirect a group to a single-node group, or boost a specific node's priority to maximum to force traffic through it.

### Reverse IP Lookup

```bash
# Find which domains resolved to a given IP
curl http://localhost:1111/lookup/1.2.3.4
```

### Static DNS Management

Static DNS entries defined in `dns.static` can be updated at runtime without restart:

```bash
# List all static entries
curl http://localhost:1111/static

# Get a specific entry
curl http://localhost:1111/static/local_nas

# Update an entry (multi-field)
curl -X PUT http://localhost:1111/static/local_nas \
  -H "Content-Type: text/plain" \
  -d $'a: 192.168.16.42\naaaa: fdfe::be24:11ff:fe64:1234\nttl: 3600'
```

> Static DNS responses are **not cached**, so updates take effect immediately.

## DNS Enhancements

### `dns_cache_tag` (`-l` annotation)

Dialers sharing the same `-l` tag use a shared DNS cache domain. This is useful when multiple dialers reside on the same VPS in the same region — they can safely share cached DNS results, reducing upstream queries:

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

Define static A, AAAA, and TXT records directly in the config. Then reference them in DNS routing via `static(name)`:

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

Force a DNS upstream query to use a specific outbound group:

```shell
qname(keyword:gemini, keyword:openai) -> proxy_dns(via: ai)
```

### `dns/race`

Query multiple upstreams concurrently and use the first response:

```shell
qname(geosite:gfw) -> race(proxy_dns, googledns)
```

### `dns/mac` + `dns/sip`

Per-client DNS filtering based on MAC address or source IP:

```shell
qtype(aaaa) && mac('11:22:33:44:55:66') -> reject
qtype(aaaa) && sip(192.168.1.100) -> reject
```

### DNS Pool Tuning

Control DNS connection pooling behavior per forwarder (keyed by upstream + dialer + target):

```shell
dns {
  udp_pool_size: 10     # UDP connections per forwarder
  udp_pool_ttl: 10m     # TTL for idle UDP connections
  tcp_pool_size: 2      # TCP connections per forwarder
  tcp_pool_ttl: 30s     # TTL for idle TCP connections
}
```

## Supported Protocols

| Protocol | Schemes | Notes |
|---|---|---|
| HTTP(S) | `http`, `https` | Generic HTTP CONNECT proxy |
| Socks5 | `socks`, `socks5` | |
| Shadowsocks | `ss`, `shadowsocks` | AEAD, stream ciphers, SS2022 (`2022-blake3-aes-*`), simple-obfs, v2ray-plugin (WS+TLS) |
| ShadowsocksR | `ssr`, `shadowsocksr` | |
| VMess | `vmess` | AEAD, alterID=0; TCP, WS, TLS, gRPC, Meek, HTTPUpgrade |
| VLESS | `vless` | Reality, gRPC, Meek, HTTPUpgrade, mux, smux |
| Trojan | `trojan`, `trojan-go` | trojan-gfw and trojan-go |
| Tuic | `tuic` | v5 |
| Juicity | `juicity` | |
| Hysteria2 | `hysteria2`, `hy2` | |
| AnyTLS | `anytls` | |
| Proxy chain | `->` | Chain multiple protocols with `->` separator |

See [docs/en/proxy-protocols.md](./docs/en/proxy-protocols.md) for URI schemas and details.

### VLESS Mux & SMux

VLESS supports both v2ray-native mux and sing-box smux for connection multiplexing. Add these query parameters to the VLESS node link:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `mux` / `multiplex` | bool | `false` | Enable v2ray-native mux |
| `smux` | bool | `false` | Enable sing-box smux |
| `mux_concurrency` | int | `8` | Max concurrent streams per connection |
| `mux_idle_timeout` | int | `300` | Idle timeout in seconds before closing a sub-connection |

> **Note:** `mux` and `smux` are incompatible with `flow` (e.g. `xtls-rprx-vision`).

Example:

```
vless://uuid@host:port?type=tcp&security=reality&smux=1&mux_concurrency=4&mux_idle_timeout=120#NodeName
```

### AnyTLS Idle Session

AnyTLS supports maintaining a pool of idle sessions to avoid the overhead of establishing new connections. Configure via URL query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `minIdleSession` | int | `0` | Minimum idle sessions kept alive for immediate use |
| `idleCheckInterval` | duration | — | How often to scan for expired idle sessions (e.g. `30s`) |
| `idleTimeout` | duration | — | Max lifetime of an idle session before recycling (e.g. `5m`) |

Example:

```
anytls://user@host:port?minIdleSession=2&idleCheckInterval=30s&idleTimeout=5m#NodeName
```

## Getting Started

Please refer to the [Quick Start Guide](./docs/en/README.md) for kernel requirements, installation, and minimal configuration.

A full example config is available at [example_next.dae](./example_next.dae).


## License

[AGPL-3.0 (C) daeuniverse](https://github.com/daeuniverse/dae/blob/main/LICENSE)

## Acknowledgements

- Original [dae](https://github.com/daeuniverse/dae) project by daeuniverse
- [dae-next](https://github.com/LostAttractor/dae) by LostAttractor
- All [contributors](https://github.com/daeuniverse/dae/graphs/contributors)
