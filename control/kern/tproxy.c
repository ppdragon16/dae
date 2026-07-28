// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

// +build ignore

// Disable implicit CO-RE from vmlinux.h to bypass bad relocation caused by GCC 15 DTE stripping UAPI structs.
#define BPF_NO_PRESERVE_ACCESS_INDEX 1

#include "headers/errno-base.h"
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/upai_in6_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
// #define __DEBUG_ROUTING
// #define __PRINT_ROUTING_RESULT
// #define __PRINT_SETUP_PROCESS_CONNNECTION
// #define __DEBUG
// #define __UNROLL_ROUTE_LOOP

#ifndef __DEBUG
#undef bpf_printk
#define bpf_printk(...) ((void)0)
#endif
// #define likely(x) x
// #define unlikely(x) x
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16

#define PACKET_HOST 0
#define PACKET_OTHERHOST 3

#define NOWHERE_IFINDEX 0

#define MAX_INTERFACE_NUM 256
#ifndef MAX_MATCH_SET_LEN
#define MAX_MATCH_SET_LEN \
	(32 * 32) // Should be sync with common/consts/ebpf.go.
#endif
#define MAX_LPM_SIZE 2048000
#define MAX_LPM_NUM (MAX_MATCH_SET_LEN + 8)
#define MAX_DST_MAPPING_NUM 65536
#define MAX_COOKIE_PID_PNAME_MAPPING_NUM 65536
#define MAX_DOMAIN_ROUTING_NUM 65536
#define MAX_ARG_LEN 128

#define UTP_MAX_EXTENSIONS 4
#define IPV6_MAX_EXTENSIONS 8

#define ipv6_optlen(p) (((p)+1) << 3)

#define OUTBOUND_DIRECT 0
#define OUTBOUND_BLOCK 1
#define OUTBOUND_MUST_RULES 0xFC
#define OUTBOUND_CONTROL_PLANE_ROUTING 0xFD
#define OUTBOUND_LOGICAL_OR 0xFE
#define OUTBOUND_LOGICAL_AND 0xFF
#define OUTBOUND_LOGICAL_MASK 0xFE

#define TPROXY_MARK 0x8000000

#define NDP_REDIRECT 137

#define PARSE_FRAGMENT 2

// Param keys:
static const __u32 zero_key;
static const __u32 one_key = 1;

// Outbound Connectivity Map:

struct outbound_connectivity_query {
	__u8 outbound;
	__u8 l4proto;
	__u8 ipversion;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct outbound_connectivity_query);
	__type(value, __u32); // true, false
	__uint(max_entries, 256 * 2 * 2); // outbound * l4proto * ipversion
} outbound_connectivity_map SEC(".maps");

// Sockmap:
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32); // 0 is tcp, 1 is udp.
	__type(value, __u64); // fd of socket.
	__uint(max_entries, 2);
} listen_socket_map SEC(".maps");

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct redirect_tuple {
	union ip6 sip;
	union ip6 dip;
};

struct redirect_entry {
	__u32 ifindex;
	__u8 smac[6];
	__u8 dmac[6];
	__u8 from_wan;
	__u8 padding[3];
	__u64 last_seen_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct redirect_tuple);
	__type(value, struct redirect_entry);
	__uint(max_entries, 65536);
} redirect_track SEC(".maps");
// Memory is allocated on demand (BPF_F_NO_PREALLOC).


struct routing_result {
	__u32 mark;
	__u8 must;
	__u8 mac[6];
	__u8 outbound;
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u32 ifindex;
	__u8 dscp;
	__u8 state;
	__u8 padding[2];
	__u64 last_seen_ns;
};

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
	__u8 l4proto;
};

struct tuples {
	struct tuples_key five;
	__u8 dscp;
};
struct dae_param {
	__u32 tproxy_port;
	__u32 control_plane_pid;
	__u32 dae0_ifindex;
	__u32 dae_netns_id;
	__u8 dae0peer_mac[6];
	__u8 padding_after_mac[2]; // pad to align use_redirect_peer
	__u8 use_redirect_peer;
	__u8 has_bpf_get_current_task;
	__u16 padding2;
	// dae_socket_mark is set on dae's own sockets to identify them.
	__u32 dae_socket_mark;
};

const volatile struct dae_param PARAM = {};

/* dae_ifindex_map holds the runtime-updatable ifindex of the dae0 device.
 * Unlike PARAM.dae0_ifindex (frozen in .rodata at load time), this ARRAY map
 * can be updated from userspace without reloading the BPF program. This allows
 * hot-recovery when the kernel recreates the netkit/veth device and assigns a
 * new ifindex. BPF falls back to PARAM.dae0_ifindex if the map is uninitialized.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} dae_ifindex_map SEC(".maps");

// routing_tuples_map uses HASH (not LRU) so the kernel never silently evicts
// entries. Active connections refresh last_seen_ns on every packet; stale
// entries are cleaned by the Go-side janitor with dual timeout (e.g. 30m for
// ACTIVE/UDP & 10s for CLOSING).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct tuples_key);
	__type(value, struct routing_result);
	__uint(max_entries, MAX_DST_MAPPING_NUM);
	__uint(pinning, LIBBPF_PIN_NONE);
} routing_tuples_map SEC(".maps");
// Memory is allocated on demand (BPF_F_NO_PREALLOC).

/* Sockets in fast_sock map are used for fast-redirecting via
 * sk_msg/fast_redirect. Sockets are automactically deleted from map once
 * closed, so we don't need to worry about stale entries.
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuples_key);
	__type(value, __u64);
	__uint(max_entries, 65535);
} fast_sock SEC(".maps");
// 1.04 MB

// Array of LPM tries:
struct lpm_key {
	struct bpf_lpm_trie_key trie_key;
	__be32 data[4];
};

struct map_lpm_type {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, MAX_LPM_SIZE);
	__uint(key_size, sizeof(struct lpm_key));
	__uint(value_size, sizeof(__u32));
} unused_lpm_type SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, MAX_LPM_NUM);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
	__array(values, struct map_lpm_type);
} lpm_array_map SEC(".maps");

enum __attribute__((packed)) MatchType {
	/// WARNING: MUST SYNC WITH common/consts/ebpf.go.
	MatchType_DomainSet,
	MatchType_IpSet,
	MatchType_SourceIpSet,
	MatchType_Port,
	MatchType_SourcePort,
	MatchType_L4Proto,
	MatchType_IpVersion,
	MatchType_Mac,
	MatchType_ProcessName,
	MatchType_IfIndex,
	MatchType_Dscp,
	MatchType_Fallback,
};

enum L4ProtoType {
	L4ProtoType_TCP = 1,
	L4ProtoType_UDP,
};

enum IpVersionType {
	IpVersionType_4 = 1,
	IpVersionType_6,
};

struct port_range {
	__u16 port_start;
	__u16 port_end;
};

/*
 * Rule is like as following:
 *
 * domain(geosite:cn, suffix: google.com) && l4proto(tcp) -> my_group
 *
 * pseudocode: domain(geosite:cn || suffix:google.com) && l4proto(tcp) ->
 * my_group
 *
 * A match_set can be: IP set geosite:cn, suffix google.com, tcp proto
 */
struct match_set {
	union {
		__u8 __value[16]; // Placeholder for bpf2go.

		__u32 index;
		struct port_range port_range;
		enum L4ProtoType l4proto_type;
		enum IpVersionType ip_version;
		__u32 pname[TASK_COMM_LEN / 4];
		__u32 ifindex;
		__u8 dscp;
	};
	bool not ; // A subrule flag (this is not a match_set flag).
	enum MatchType type;
	__u8 outbound; // User-defined value range is [0, 252].
	bool must;
	__u32 mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct match_set);
	__uint(max_entries, MAX_MATCH_SET_LEN);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing_map SEC(".maps");

// key=0: active routing rules length in routing_map.
// Populated by Go at load time, read by route() to optimize bpf_loop.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} routing_meta_map SEC(".maps");

struct domain_routing {
	__u32 bitmap[MAX_MATCH_SET_LEN / 32];
};

// domain_routing_map / domain_bump_map are fully managed by user space
// (control plane). Use BPF_MAP_TYPE_HASH (not LRU) so the kernel never
// silently evicts entries; entries are only inserted/removed when user
// space adds/removes a DNS lookup cache entry, keeping the two states
// in sync.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __be32[4]);
	__type(value, struct domain_routing);
	__uint(max_entries, MAX_DOMAIN_ROUTING_NUM);
	/// NOTICE: No persistence.
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_routing_map SEC(".maps");
// 13.63 MB

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __be32[4]);
	__type(value, struct domain_routing);
	__uint(max_entries, MAX_DOMAIN_ROUTING_NUM);
	/// NOTICE: No persistence.
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_bump_map SEC(".maps");
// 13.63 MB


struct pid_pname {
	__u64 last_seen_ns;
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct pid_pname);
	__uint(max_entries, MAX_COOKIE_PID_PNAME_MAPPING_NUM);
	/// NOTICE: No persistence.
	__uint(pinning, LIBBPF_PIN_NONE);
} cookie_pid_map SEC(".maps");
// Memory is allocated on demand (BPF_F_NO_PREALLOC).

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} exited_map SEC(".maps");

// Per-CPU scratch maps to stay under 512-byte stack limit.

struct parse_transport_ctx {
	struct ethhdr ethh;
	struct iphdr iph;
	struct ipv6hdr ipv6h;
	struct icmp6hdr icmp6h;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 ihl;
	__u8 l4proto;
	__u8 listener_l4proto;
	__u8 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parse_transport_ctx);
	__uint(max_entries, 1);
} parse_ctx_scratch_map SEC(".maps");

struct parsed_packet {
	struct ethhdr ethh;
	struct tuples tuples;
	struct tcphdr tcph;
	struct udphdr udph;
	__u8 l4proto;
	__u8 listener_l4proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct parsed_packet);
	__uint(max_entries, 1);
} pkt_scratch_map SEC(".maps");

enum route_state_flags {
	ROUTE_STATE_BAD_RULE     = BIT(0),
	ROUTE_STATE_GOOD_SUBRULE = BIT(1),
	ROUTE_STATE_MUST         = BIT(2),
	ROUTE_STATE_DNS_QUERY    = BIT(3),
	ROUTE_STATE_DOMAIN_BUMP  = BIT(4), // dae_ppdn: domain_bump_map hit → need control plane
};

struct route_ctx {
	__u32 flag[8];
	__u8 is_wan;
	__be32 mac[4];
	__u16 h_dport;
	__u16 h_sport;
	__s64 result;
	struct lpm_key lpm_key_saddr, lpm_key_daddr, lpm_key_mac;
	__u32 domain_word_idx;
	__u32 domain_word_bits;
	bool domain_word_cached;
	__u8 route_state;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct route_ctx);
	__uint(max_entries, 1);
} route_ctx_scratch_map SEC(".maps");

// Connection state constants for routing results.
enum routing_result_state {
	STATE_ACTIVE = 0,
	STATE_CLOSING = 1,  // Go-side closeRoutingTuplesEntry sets this for both TCP and UDP
};

// Functions:

static __always_inline __u8 ipv4_get_dscp(const struct iphdr *iph)
{
	return (iph->tos & 0xfc) >> 2;
}

static __always_inline __u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h)
{
	const __u8 *version_and_tc = (const __u8 *)ipv6h;

	/* Read DSCP from raw bytes to avoid bitfield layout variability. */
	return ((version_and_tc[0] & 0x0f) << 2) | (version_and_tc[1] >> 6);
}

__attribute__((unused)) static __always_inline void
get_tuples(const struct __sk_buff *skb, struct tuples *tuples,
	   const struct iphdr *iph, const struct ipv6hdr *ipv6h,
	   const struct tcphdr *tcph, const struct udphdr *udph, __u8 l4proto)
{
	__builtin_memset(tuples, 0, sizeof(*tuples));
	tuples->five.l4proto = l4proto;

	// Both iph and ipv6h are stack-allocated; check version field.
	if (iph->version == 4) {
		tuples->five.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.sip.u6_addr32[3] = iph->saddr;

		tuples->five.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuples->five.dip.u6_addr32[3] = iph->daddr;

		tuples->dscp = ipv4_get_dscp(iph);

	} else {
		// IPv6
		__builtin_memcpy(&tuples->five.dip, &ipv6h->daddr,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&tuples->five.sip, &ipv6h->saddr,
				 IPV6_BYTE_LENGTH);

		tuples->dscp = ipv6_get_dscp(ipv6h);
	}
	if (l4proto == IPPROTO_TCP && tcph) {
		tuples->five.sport = tcph->source;
		tuples->five.dport = tcph->dest;
	} else if (udph) {
		tuples->five.sport = udph->source;
		tuples->five.dport = udph->dest;
	}
}

static __always_inline __u8
tcp_listener_l4proto(const struct tcphdr *tcph)
{
	return tcph && tcph->syn && !tcph->ack ? IPPROTO_TCP : 0;
}

static __always_inline bool equal16(const __be32 x[4], const __be32 y[4])
{
	return ((__be64 *)x)[0] == ((__be64 *)y)[0] &&
	       ((__be64 *)x)[1] == ((__be64 *)y)[1];
}

static __always_inline bool is_extension_header(__u8 nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
		return true;
	default:
		return false;
	}
}

// Fast-path packet parsing via bpf_skb_pull_data + direct access.
// Returns 0 on success, -1 for slow-path fallback, -EFAULT for malformed,
// PARSE_FRAGMENT for non-initial fragments.
static __always_inline int
parse_transport_fast(struct __sk_buff *skb, __u32 link_h_len,
		     struct parse_transport_ctx *ctx)
{
	struct ethhdr *ethh = &ctx->ethh;
	struct iphdr *iph = &ctx->iph;
	struct ipv6hdr *ipv6h = &ctx->ipv6h;
	struct icmp6hdr *icmp6h = &ctx->icmp6h;
	struct tcphdr *tcph = &ctx->tcph;
	struct udphdr *udph = &ctx->udph;
	__u8 *ihl = &ctx->ihl;
	__u8 *l4proto = &ctx->l4proto;
	__u8 *listener_l4proto = &ctx->listener_l4proto;

	void *data, *data_end;
	__u32 offset = 0;

	*ihl = 0;
	*l4proto = 0;
	*listener_l4proto = 0;
	__builtin_memset(ethh, 0, sizeof(struct ethhdr));
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	// Pull 128 bytes: eth(14)+IP(20)+TCP(20)+options.
#define HEADER_PULL_SIZE 128
	if (bpf_skb_pull_data(skb, HEADER_PULL_SIZE))
		return -1;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// Parse Ethernet header (or L3-only)
	if (link_h_len == ETH_HLEN) {
		struct ethhdr *eth_ptr = data;

		if ((void *)(eth_ptr + 1) > data_end)
			return -1;

		ethh->h_proto = eth_ptr->h_proto;
		ethh->h_dest[0] = eth_ptr->h_dest[0];
		ethh->h_dest[1] = eth_ptr->h_dest[1];
		ethh->h_dest[2] = eth_ptr->h_dest[2];
		ethh->h_dest[3] = eth_ptr->h_dest[3];
		ethh->h_dest[4] = eth_ptr->h_dest[4];
		ethh->h_dest[5] = eth_ptr->h_dest[5];
		ethh->h_source[0] = eth_ptr->h_source[0];
		ethh->h_source[1] = eth_ptr->h_source[1];
		ethh->h_source[2] = eth_ptr->h_source[2];
		ethh->h_source[3] = eth_ptr->h_source[3];
		ethh->h_source[4] = eth_ptr->h_source[4];
		ethh->h_source[5] = eth_ptr->h_source[5];
		offset += sizeof(struct ethhdr);
	} else {
		ethh->h_proto = skb->protocol;
	}

	// Parse IP header
	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph_ptr = data + offset;

		if ((void *)(iph_ptr + 1) > data_end)
			return -1;
		// Malformed IP header: ihl < 5 is invalid, no point falling back
		if (iph_ptr->ihl < 5)
			return -EFAULT;

		// Copy saddr/daddr early so get_tuples() works for PARSE_FRAGMENT.
		iph->version = iph_ptr->version;
		iph->ihl = iph_ptr->ihl;
		iph->tos = iph_ptr->tos;
		iph->protocol = iph_ptr->protocol;
		iph->saddr = iph_ptr->saddr;
		iph->daddr = iph_ptr->daddr;
		*ihl = iph_ptr->ihl;
		*l4proto = iph_ptr->protocol;

		__u32 ip_hdr_len = iph_ptr->ihl * 4;
		__u32 l4_offset = offset + ip_hdr_len;

		// First fragment carries L4 header; non-initial fragments fall back.
		__u16 frag_off = bpf_ntohs(iph_ptr->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		switch (iph->protocol) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + l4_offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			tcph->doff = tcph_ptr->doff;
			tcph->rst = tcph_ptr->rst;
			tcph->syn = tcph_ptr->syn;
			tcph->fin = tcph_ptr->fin;
			tcph->window = tcph_ptr->window;
			*listener_l4proto = tcp_listener_l4proto(tcph_ptr);
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + l4_offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -1;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			*listener_l4proto = IPPROTO_UDP;
			return 0;
		}
		default:
			return 1;
		}
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h_ptr = data + offset;

		if ((void *)(ipv6h_ptr + 1) > data_end)
			return -1;

		/* Preserve version, traffic class, and flow label for DSCP extraction. */
		__builtin_memcpy(ipv6h, ipv6h_ptr, 4);
		ipv6h->nexthdr = ipv6h_ptr->nexthdr;
		ipv6h->payload_len = ipv6h_ptr->payload_len;
		__u32 *saddr_dst = (__u32 *)ipv6h->saddr.in6_u.u6_addr32;
		const __u32 *saddr_src = (const __u32 *)ipv6h_ptr->saddr.in6_u.u6_addr32;

		saddr_dst[0] = saddr_src[0];
		saddr_dst[1] = saddr_src[1];
		saddr_dst[2] = saddr_src[2];
		saddr_dst[3] = saddr_src[3];
		__u32 *daddr_dst = (__u32 *)ipv6h->daddr.in6_u.u6_addr32;
		const __u32 *daddr_src = (const __u32 *)ipv6h_ptr->daddr.in6_u.u6_addr32;

		daddr_dst[0] = daddr_src[0];
		daddr_dst[1] = daddr_src[1];
		daddr_dst[2] = daddr_src[2];
		daddr_dst[3] = daddr_src[3];

		*l4proto = ipv6h_ptr->nexthdr;
		*ihl = sizeof(struct ipv6hdr) / 4;
		offset += sizeof(struct ipv6hdr);

		__u8 nexthdr = ipv6h_ptr->nexthdr;
		const __u8 *ext_hdr;

		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// First fragment still has L4; non-initial falls back.
				struct frag_hdr *fragh = data + offset;

				if ((void *)(fragh + 1) > data_end)
					return -1;
				__u16 frag_off = bpf_ntohs(fragh->frag_off);

				nexthdr = fragh->nexthdr;
				*l4proto = nexthdr;
				offset += sizeof(*fragh);
				if ((frag_off & 0xFFF8) != 0)
					return PARSE_FRAGMENT;
				continue;
			}
			if (!is_extension_header(nexthdr))
				break;

			ext_hdr = data + offset;
			if ((void *)(ext_hdr + 2) > data_end)
				return -1;

			nexthdr = ext_hdr[0];
			offset += ipv6_optlen(ext_hdr[1]);
			*l4proto = nexthdr;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		// L4 parsing for IPv6
		switch (nexthdr) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph_ptr = data + offset;

			if ((void *)(tcph_ptr + 1) > data_end)
				return -1;
			tcph->source = tcph_ptr->source;
			tcph->dest = tcph_ptr->dest;
			tcph->seq = tcph_ptr->seq;
			tcph->ack_seq = tcph_ptr->ack_seq;
			tcph->doff = tcph_ptr->doff;
			tcph->rst = tcph_ptr->rst;
			tcph->syn = tcph_ptr->syn;
			tcph->fin = tcph_ptr->fin;
			tcph->window = tcph_ptr->window;
			*listener_l4proto = tcp_listener_l4proto(tcph_ptr);
			return 0;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph_ptr = data + offset;

			if ((void *)(udph_ptr + 1) > data_end)
				return -1;
			udph->source = udph_ptr->source;
			udph->dest = udph_ptr->dest;
			udph->len = udph_ptr->len;
			udph->check = udph_ptr->check;
			*listener_l4proto = IPPROTO_UDP;
			return 0;
		}
		case IPPROTO_ICMPV6: {
			struct icmp6hdr *icmp6h_ptr = data + offset;

			if ((void *)(icmp6h_ptr + 1) > data_end)
				return -1;
			icmp6h->icmp6_type = icmp6h_ptr->icmp6_type;
			icmp6h->icmp6_code = icmp6h_ptr->icmp6_code;
			return 0;
		}
		default:
			return 1;
		}
	}

	return 1;
}

// Slow-path fallback using bpf_skb_load_bytes.
static __always_inline int
parse_transport_slow(struct __sk_buff *skb, __u32 link_h_len,
		     struct parse_transport_ctx *ctx)
{
	struct ethhdr *ethh = &ctx->ethh;
	struct iphdr *iph = &ctx->iph;
	struct ipv6hdr *ipv6h = &ctx->ipv6h;
	struct icmp6hdr *icmp6h = &ctx->icmp6h;
	struct tcphdr *tcph = &ctx->tcph;
	struct udphdr *udph = &ctx->udph;
	__u8 *ihl = &ctx->ihl;
	__u8 *l4proto = &ctx->l4proto;
	__u8 *listener_l4proto = &ctx->listener_l4proto;

	__u32 offset = 0;
	int ret;

	if (link_h_len == ETH_HLEN) {
		ret = bpf_skb_load_bytes(skb, offset, ethh,
					 sizeof(struct ethhdr));
		if (ret)
			return 1;
		offset += sizeof(struct ethhdr);
	} else {
		__builtin_memset(ethh, 0, sizeof(struct ethhdr));
		ethh->h_proto = skb->protocol;
	}

	*ihl = 0;
	*l4proto = 0;
	*listener_l4proto = 0;
	__builtin_memset(iph, 0, sizeof(struct iphdr));
	__builtin_memset(ipv6h, 0, sizeof(struct ipv6hdr));
	__builtin_memset(icmp6h, 0, sizeof(struct icmp6hdr));
	__builtin_memset(tcph, 0, sizeof(struct tcphdr));
	__builtin_memset(udph, 0, sizeof(struct udphdr));

	if (ethh->h_proto == bpf_htons(ETH_P_IP)) {
		ret = bpf_skb_load_bytes(skb, offset, iph,
					 sizeof(struct iphdr));
		if (ret)
			return -EFAULT;
		if (iph->ihl < 5)
			return -EFAULT;
		*ihl = iph->ihl;
		*l4proto = iph->protocol;

		// First fragment carries L4; non-initial falls back.
		__u16 frag_off = bpf_ntohs(iph->frag_off);

		if ((frag_off & 0x1FFF) != 0)
			return PARSE_FRAGMENT;

		offset += iph->ihl * 4;

		switch (iph->protocol) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = tcp_listener_l4proto(tcph);
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = IPPROTO_UDP;
			break;
		default:
			return 1;
		}
		return 0;
	}

	if (ethh->h_proto == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb, offset, ipv6h,
					 sizeof(struct ipv6hdr));
		if (ret)
			return -EFAULT;

		offset += sizeof(struct ipv6hdr);
		*ihl = sizeof(struct ipv6hdr) / 4;
		__u8 nexthdr = ipv6h->nexthdr;

		// Skip extension headers using bpf_skb_load_bytes
		for (int i = 0; i < IPV6_MAX_EXTENSIONS; i++) {
			if (nexthdr == IPPROTO_NONE)
				return -EFAULT;
			if (nexthdr == IPPROTO_FRAGMENT) {
				// First fragment still has L4; non-initial falls back.
				struct frag_hdr fragh = {};

				ret = bpf_skb_load_bytes(skb, offset, &fragh,
							 sizeof(fragh));
				if (ret)
					return -EFAULT;
				nexthdr = fragh.nexthdr;
				*l4proto = nexthdr;
				offset += sizeof(fragh);
				if ((bpf_ntohs(fragh.frag_off) & 0xFFF8) != 0)
					return PARSE_FRAGMENT;
				continue;
			}

			if (!is_extension_header(nexthdr))
				break;

			ret = bpf_skb_load_bytes(skb, offset, &nexthdr, 1);
			if (ret)
				return -EFAULT;

			__u8 hdr_ext_len = 0;

			ret = bpf_skb_load_bytes(skb, offset + 1, &hdr_ext_len,
						 sizeof(hdr_ext_len));
			if (ret)
				return -EFAULT;

			__u32 ext_len = ipv6_optlen(hdr_ext_len);

			offset += ext_len;
		}

		if (is_extension_header(nexthdr))
			return -EFAULT;

		*l4proto = nexthdr;
		switch (nexthdr) {
		case IPPROTO_TCP:
			ret = bpf_skb_load_bytes(skb, offset, tcph,
						 sizeof(struct tcphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = tcp_listener_l4proto(tcph);
			break;
		case IPPROTO_UDP:
			ret = bpf_skb_load_bytes(skb, offset, udph,
						 sizeof(struct udphdr));
			if (ret)
				return -EFAULT;
			*listener_l4proto = IPPROTO_UDP;
			break;
		case IPPROTO_ICMPV6:
			ret = bpf_skb_load_bytes(skb, offset, icmp6h,
						 sizeof(struct icmp6hdr));
			if (ret)
				return -EFAULT;
			break;
		default:
			return 1;
		}
		return 0;
	}

	return 1;
}

// Try fast path first; fall back to slow path on -1.
static __always_inline int
parse_transport(struct __sk_buff *skb, __u32 link_h_len,
		struct parse_transport_ctx *ctx)
{
	int ret = parse_transport_fast(skb, link_h_len, ctx);

	if (ret == -1)
		return parse_transport_slow(skb, link_h_len, ctx);
	return ret;
}

static __always_inline int
parse_packet(struct __sk_buff *skb, __u32 link_h_len,
	     struct parsed_packet *out)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	int ret = parse_transport(skb, link_h_len, ctx);

	if (ret < 0)
		return ret;
	if (ctx->l4proto == IPPROTO_ICMPV6)
		return 1;

	// PARSE_FRAGMENT still populates the IP tuple for callers.
	__builtin_memset(out, 0, sizeof(*out));
	out->ethh = ctx->ethh;
	out->tcph = ctx->tcph;
	out->udph = ctx->udph;
	out->l4proto = ctx->l4proto;
	out->listener_l4proto = ctx->listener_l4proto;
	get_tuples(skb, &out->tuples, &ctx->iph, &ctx->ipv6h, &ctx->tcph, &ctx->udph, ctx->l4proto);
	return ret;
}


// Only work for first packet of a new connection.
static __always_inline bool
is_utp(const struct __sk_buff *skb, __u8 l4proto, __u32 offset)
{
	if (l4proto != IPPROTO_UDP || skb->len < (offset + 160)) {
		return false;
	}

	__u8 header[2];
    int ret = bpf_skb_load_bytes(skb, offset, header, sizeof(header));
	if (ret)
		return false;

    __u8 typ = header[0] >> 4;
	__u8 version = header[0] & 0x0F;
	if (version != 1 || typ > 4)
		return false;

	__u8 extension = header[1];

	u32 timestamp_difference_microseconds;
	ret = bpf_skb_load_bytes(skb, offset+64, &timestamp_difference_microseconds, sizeof(timestamp_difference_microseconds));
	if (ret)
		return false;
	if (timestamp_difference_microseconds != 0)
		return false; // This should be 0. for new connection.

	offset += 160;

	for (int i = 0; i < UTP_MAX_EXTENSIONS; i++) {
		if (extension == 0) {
			return true;
		}
		if (extension > 0x04)
			return false;

		ret = bpf_skb_load_bytes(skb, offset, header, sizeof(header));
		if (ret)
			return false;

		extension = header[0];
		offset += header[1] + sizeof(header);
	}
	return false;
}


static __always_inline int
route_match_lpm(struct route_ctx *ctx, const struct match_set *match_set,
		struct lpm_key *lpm_key)
{
	struct map_lpm_type *lpm;

	lpm = bpf_map_lookup_elem(&lpm_array_map, &match_set->index);
	if (unlikely(!lpm)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (bpf_map_lookup_elem(lpm, lpm_key)) {
		// match_set hits.
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
	}
	return 0;
}

static __always_inline struct lpm_key *
route_select_lpm_key(struct route_ctx *ctx, __u8 match_type)
{
	if (match_type == MatchType_Mac)
		return &ctx->lpm_key_mac;
	if (match_type == MatchType_IpSet)
		return &ctx->lpm_key_daddr;
	return &ctx->lpm_key_saddr;
}

static __always_inline int route_match_domain_set(struct route_ctx *ctx,
						  __u32 index)
{
	__u32 bitmap_word_idx = index / 32;
	struct domain_routing *domain_routing;

	if (unlikely(bitmap_word_idx >= MAX_MATCH_SET_LEN / 32)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (!ctx->domain_word_cached || ctx->domain_word_idx != bitmap_word_idx) {
		// Refresh one 32-rule bitmap word at a time.
		__be32 daddr[4];

		__builtin_memcpy(daddr, ctx->lpm_key_daddr.data, sizeof(daddr));
		domain_routing = bpf_map_lookup_elem(&domain_routing_map, daddr);
		ctx->domain_word_idx = bitmap_word_idx;
		if (domain_routing)
			ctx->domain_word_bits =
				domain_routing->bitmap[bitmap_word_idx];
		else
			ctx->domain_word_bits = 0;
		ctx->domain_word_cached = true;
	}

	if ((ctx->domain_word_bits >> (index % 32)) & 1) {
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
	} else {
		// dae_ppdn: also check domain_bump_map for partial domain matches
		struct domain_routing *domain_bump;
		__be32 daddr[4];

		__builtin_memcpy(daddr, ctx->lpm_key_daddr.data, sizeof(daddr));
		domain_bump = bpf_map_lookup_elem(&domain_bump_map, daddr);
		if (domain_bump &&
		    (domain_bump->bitmap[index / 32] >> (index % 32)) & 1) {
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
			ctx->route_state |= ROUTE_STATE_DOMAIN_BUMP;
		}
	}
	return 0;
}

static __always_inline int
route_eval_match(struct route_ctx *ctx, const struct match_set *match_set,
		 __u32 index, __u8 l4proto_type, __u8 ipversion_type,
		 const __u32 *pname, __u8 is_wan, __u8 dscp)
{
	__u8 match_type = match_set->type;

	switch (match_type) {
	case MatchType_Mac:
	case MatchType_IpSet:
	case MatchType_SourceIpSet:
	{
		struct lpm_key *lpm_key = route_select_lpm_key(ctx, match_type);

#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: lpm_key_map, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
		bpf_printk("\tip: %pI6", lpm_key->data);
#endif
		if (route_match_lpm(ctx, match_set, lpm_key))
			return 1;
		break;
	}
	case MatchType_Port:
	case MatchType_SourcePort:
	{
		__u16 check_port = match_type == MatchType_Port ? ctx->h_dport :
							      ctx->h_sport;
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: h_port_map, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
		bpf_printk("\tport: %u, range: [%u, %u]", check_port,
			   match_set->port_range.port_start,
			   match_set->port_range.port_end);
#endif
		if (check_port >= match_set->port_range.port_start &&
		    check_port <= match_set->port_range.port_end)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	}
	case MatchType_L4Proto:
	case MatchType_IpVersion:
	{
		__u8 value = match_type == MatchType_L4Proto ? l4proto_type :
							      ipversion_type;
		__u8 mask = match_type == MatchType_L4Proto ?
				    match_set->l4proto_type :
				    match_set->ip_version;
#ifdef __DEBUG_ROUTING
		if (match_type == MatchType_L4Proto) {
			bpf_printk(
				"CHECK: l4proto, match_set->type: %u, not: %d, outbound: %u",
				match_type, match_set->not,
				match_set->outbound);
		} else {
			bpf_printk(
				"CHECK: ipversion, match_set->type: %u, not: %d, outbound: %u",
				match_type, match_set->not,
				match_set->outbound);
		}
#endif
		if (value & mask)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	}
	case MatchType_DomainSet:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: domain, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (route_match_domain_set(ctx, index))
			return 1;
		break;
	case MatchType_ProcessName:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: pname, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (is_wan && equal16(match_set->pname, pname))
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_IfIndex:
		if (dscp == match_set->ifindex)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_Dscp:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: dscp, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		if (dscp == match_set->dscp)
			ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	case MatchType_Fallback:
#ifdef __DEBUG_ROUTING
		bpf_printk("CHECK: hit fallback");
#endif
		ctx->route_state |= ROUTE_STATE_GOOD_SUBRULE;
		break;
	default:
#ifdef __DEBUG_ROUTING
		bpf_printk(
			"CHECK: <unknown>, match_set->type: %u, not: %d, outbound: %u",
			match_type, match_set->not, match_set->outbound);
#endif
		ctx->result = -EINVAL;
		return 1;
	}

	return 0;
}

static __always_inline int
route_finalize_match(struct route_ctx *ctx, const struct match_set *match_set)
{
	__u8 match_outbound = match_set->outbound;
	bool match_not = match_set->not;

#ifdef __DEBUG_ROUTING
	bpf_printk("good_subrule: %d, bad_rule: %d",
		   !!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE),
		   !!(ctx->route_state & ROUTE_STATE_BAD_RULE));
#endif
	if (match_outbound != OUTBOUND_LOGICAL_OR) {
		// This match_set reaches the end of subrule.
		if (!!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE) == match_not)
			// This subrule does not hit.
			ctx->route_state |= ROUTE_STATE_BAD_RULE;

		// Reset good_subrule.
		ctx->route_state &= ~ROUTE_STATE_GOOD_SUBRULE;
	}
#ifdef __DEBUG_ROUTING
	bpf_printk("_bad_rule: %d", !!(ctx->route_state & ROUTE_STATE_BAD_RULE));
#endif
	if ((match_outbound & OUTBOUND_LOGICAL_MASK) != OUTBOUND_LOGICAL_MASK) {
		// Tail of a rule (line).
		// Decide whether to hit.
		if (!(ctx->route_state & ROUTE_STATE_BAD_RULE)) {
#ifdef __DEBUG_ROUTING
			bpf_printk(
				"MATCHED: match_set->type: %u, match_set->not: %d",
				match_set->type, match_not);
#endif
			// DNS requests should routed by control plane if outbound is not
			// must_direct.
			if (unlikely(match_outbound == OUTBOUND_MUST_RULES)) {
				ctx->route_state |= ROUTE_STATE_MUST;
			} else {
				bool must = !!(ctx->route_state & ROUTE_STATE_MUST) ||
					    match_set->must;

				if (!must &&
				    (ctx->route_state & (ROUTE_STATE_DNS_QUERY |
							 ROUTE_STATE_DOMAIN_BUMP))) {
					ctx->result =
						(__s64)OUTBOUND_CONTROL_PLANE_ROUTING |
						((__s64)match_set->mark << 8) |
						((__s64)must << 40);
#ifdef __DEBUG_ROUTING
					bpf_printk(
						"OUTBOUND_CONTROL_PLANE_ROUTING: %ld",
						ctx->result);
#endif
					return 1;
				}
				ctx->result = (__s64)match_outbound |
					      ((__s64)match_set->mark << 8) |
					      ((__s64)must << 40);
#ifdef __DEBUG_ROUTING
				bpf_printk("outbound %u: %ld",
					   match_outbound, ctx->result);
#endif
				return 1;
			}
		}
		ctx->route_state &= ~ROUTE_STATE_BAD_RULE;
	}
	return 0;
}

struct route_loop_ctx {
	struct route_ctx *work;
};

static __noinline int route_loop_cb(__u32 index, void *data)
{
	struct route_loop_ctx *loop = data;
	struct route_ctx *ctx = loop->work;
	struct match_set *match_set;
	__u8 l4proto_type = ctx->flag[0];
	__u8 ipversion_type = ctx->flag[1];
	const __u32 *pname = &ctx->flag[2];
	__u8 is_wan = ctx->is_wan;
	__u8 dscp = ctx->flag[6];
	__u32 ifindex_val = ctx->flag[7];

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	if (unlikely(index >= MAX_MATCH_SET_LEN)) {
		ctx->result = -EFAULT;
		return 1;
	}

	__u32 k = index; // Clone to pass code checker.

	match_set = bpf_map_lookup_elem(&routing_map, &k);
	if (unlikely(!match_set)) {
		ctx->result = -EFAULT;
		return 1;
	}

	if (!(ctx->route_state &
	      (ROUTE_STATE_BAD_RULE | ROUTE_STATE_GOOD_SUBRULE))) {
		// Fix up dscp for IfIndex match type
		__u8 effective_dscp = dscp;
		if (match_set->type == MatchType_IfIndex)
			effective_dscp = ifindex_val;
		if (route_eval_match(ctx, match_set, k, l4proto_type,
				     ipversion_type, pname, is_wan, effective_dscp))
			return 1;
	} else {
#ifdef __DEBUG_ROUTING
		bpf_printk("key(match_set->type): %llu", match_set->type);
		bpf_printk("Skip to judge. bad_rule: %d, good_subrule: %d",
			   !!(ctx->route_state & ROUTE_STATE_GOOD_SUBRULE),
			   !!(ctx->route_state & ROUTE_STATE_BAD_RULE));
#endif
	}

	return route_finalize_match(ctx, match_set);
}

static __noinline __s64 route(const __u32 *flag, const void *l4hdr,
			      const __be32 *saddr, const __be32 *daddr,
			      const __be32 *mac)
{
#define _l4proto_type flag[0]
#define _ipversion_type flag[1]
#define _pname (&flag[2])
#define _is_wan flag[7]
#define _dscp flag[6]

	__u32 scratch_key = 0;
	struct route_ctx *ctx =
		bpf_map_lookup_elem(&route_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return -EFAULT;

	__builtin_memset(ctx, 0, sizeof(*ctx));
	__builtin_memcpy(ctx->flag, flag, sizeof(ctx->flag));
	ctx->is_wan = _is_wan;
	__builtin_memcpy(ctx->mac, mac, sizeof(ctx->mac));
	ctx->result = -ENOEXEC;

	// Variables for further use.
	if (_l4proto_type == L4ProtoType_TCP) {
		ctx->h_dport = bpf_ntohs(((struct tcphdr *)l4hdr)->dest);
		ctx->h_sport =
			bpf_ntohs(((struct tcphdr *)l4hdr)->source);
	} else {
		ctx->h_dport = bpf_ntohs(((struct udphdr *)l4hdr)->dest);
		ctx->h_sport =
			bpf_ntohs(((struct udphdr *)l4hdr)->source);
	}

	// Rule is like: domain(suffix:baidu.com, suffix:google.com) && port(443) ->
	// proxy Subrule is like: domain(suffix:baidu.com, suffix:google.com) Match
	// set is like: suffix:baidu.com
	ctx->route_state =
		(ctx->h_dport == 53 &&
		 (_l4proto_type == L4ProtoType_UDP ||
		  _l4proto_type == L4ProtoType_TCP))
		? ROUTE_STATE_DNS_QUERY
		: 0;

	ctx->lpm_key_saddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx->lpm_key_daddr.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	ctx->lpm_key_mac.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	__builtin_memcpy(ctx->lpm_key_saddr.data, saddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx->lpm_key_daddr.data, daddr,
			 IPV6_BYTE_LENGTH);
	__builtin_memcpy(ctx->lpm_key_mac.data, mac, IPV6_BYTE_LENGTH);

	int ret;

	struct route_loop_ctx loop_ctx = {
		.work = ctx,
	};
	__u32 active_rules_len = MAX_MATCH_SET_LEN;
	__u32 *rules_len_ptr =
		bpf_map_lookup_elem(&routing_meta_map, &zero_key);

	if (rules_len_ptr && *rules_len_ptr <= MAX_MATCH_SET_LEN)
		active_rules_len = *rules_len_ptr;

	ret = bpf_loop(active_rules_len, route_loop_cb, &loop_ctx, 0);
	if (unlikely(ret < 0))
		return ret;
	if (ctx->result >= 0)
		return ctx->result;
#ifdef __DEBUG_ROUTING
	bpf_printk(
		"No match_set hits. Did coder forget to sync common/consts/ebpf.go with enum MatchType?");
#endif
	return -EPERM;
#undef _l4proto_type
#undef _ipversion_type
#undef _pname
#undef _is_wan
#undef _dscp
}

/* get_dae0_ifindex returns the current dae0 ifindex, preferring the
 * runtime-updatable map over the frozen rodata constant. This allows
 * transparent recovery when dae0 is recreated with a new ifindex.
 */
static __always_inline __u32 get_dae0_ifindex(void)
{
	__u32 key = 0;
	__u32 *val = bpf_map_lookup_elem(&dae_ifindex_map, &key);

	if (val)
		return *val;
	return PARAM.dae0_ifindex;
}

static __always_inline int redirect_to_control_plane_ingress(void)
{
	__u32 ifindex = get_dae0_ifindex();

	// bpf_redirect_peer requires kernel >= 6.8 (CVE-2025-37959 fix).
	if (PARAM.use_redirect_peer)
		return bpf_redirect_peer(ifindex, 0);
	return bpf_redirect(ifindex, 0);
}

static __always_inline int redirect_to_control_plane_egress(void)
{
	__u32 ifindex = get_dae0_ifindex();

	// bpf_redirect_peer() is NOT supported in egress direction.
	return bpf_redirect(ifindex, 0);
}

static __always_inline int assign_listener(struct __sk_buff *skb, __u8 l4proto)
{
	struct bpf_sock *sk;

	if (l4proto == IPPROTO_TCP)
		sk = bpf_map_lookup_elem(&listen_socket_map, &zero_key);
	else
		sk = bpf_map_lookup_elem(&listen_socket_map, &one_key);

	if (!sk)
		return -1;

	int ret = bpf_sk_assign(skb, sk, 0);

	bpf_sk_release(sk);
	return ret;
}

static __always_inline void
fill_redirect_tuple_from_forward_packet(const struct __sk_buff *skb,
					const struct tuples *tuples,
					struct redirect_tuple *redirect_tuple)
{
	__builtin_memset(redirect_tuple, 0, sizeof(*redirect_tuple));
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		redirect_tuple->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->sip.u6_addr32[3] = tuples->five.sip.u6_addr32[3];
		redirect_tuple->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->dip.u6_addr32[3] = tuples->five.dip.u6_addr32[3];
	} else {
		__builtin_memcpy(&redirect_tuple->sip, &tuples->five.sip,
				 IPV6_BYTE_LENGTH);
		__builtin_memcpy(&redirect_tuple->dip, &tuples->five.dip,
				 IPV6_BYTE_LENGTH);
	}
}

static __always_inline void
fill_redirect_entry_from_forward_packet(__u32 ifindex, __u32 link_h_len,
					const struct ethhdr *ethh, __u8 from_wan,
					struct redirect_entry *redirect_entry)
{
	__builtin_memset(redirect_entry, 0, sizeof(*redirect_entry));
	redirect_entry->ifindex = ifindex;
	redirect_entry->from_wan = from_wan;
	redirect_entry->last_seen_ns = bpf_ktime_get_ns();
	if (link_h_len == ETH_HLEN && ethh) {
		__builtin_memcpy(redirect_entry->smac, ethh->h_source, 6);
		__builtin_memcpy(redirect_entry->dmac, ethh->h_dest, 6);
	}
}

static __always_inline int
publish_redirect_track_for_packet(struct __sk_buff *skb, __u32 link_h_len,
				  const struct tuples *tuples,
				  const struct ethhdr *ethh, __u8 from_wan)
{
	struct redirect_tuple redirect_tuple = {};
	struct redirect_entry redirect_entry = {};
	long map_ret;

	fill_redirect_tuple_from_forward_packet(skb, tuples, &redirect_tuple);
	fill_redirect_entry_from_forward_packet(skb->ifindex, link_h_len, ethh,
						from_wan, &redirect_entry);

	map_ret = bpf_map_update_elem(&redirect_track, &redirect_tuple,
				      &redirect_entry, BPF_ANY);
	if (map_ret) {
		bpf_printk("redirect_track update failed: %d", (int)map_ret);
		return (int)map_ret;
	}
	return 0;
}

static __always_inline int
rewrite_packet_for_control_plane(struct __sk_buff *skb, __u32 link_h_len,
				 __u8 from_wan)
{
	bool use_redirect_peer = PARAM.use_redirect_peer && !from_wan;
	int ret;

	if (!use_redirect_peer) {
		if (!link_h_len) {
			__u16 l3proto = skb->protocol;
			__u8 zero_mac[6] = {0};

			ret = bpf_skb_change_head(skb, sizeof(struct ethhdr), 0);
			if (ret) {
				bpf_printk("prep_redirect: bpf_skb_change_head failed: %d", ret);
				return ret;
			}
			ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto),
						  &l3proto, sizeof(l3proto), 0);
			if (ret)
				return ret;
			ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
						  zero_mac, sizeof(zero_mac), 0);
			if (ret)
				return ret;
		}

		ret = bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
					  (void *)&PARAM.dae0peer_mac, 6, 0);
		if (ret)
			return ret;
	}
	return 0;
}

static __noinline int prep_redirect_to_control_plane(
	struct __sk_buff *skb, __u32 link_h_len, struct tuples *tuples,
	struct ethhdr *ethh, __u8 from_wan)
{
	int ret = rewrite_packet_for_control_plane(skb, link_h_len, from_wan);

	if (ret)
		return ret;
	return publish_redirect_track_for_packet(skb, link_h_len, tuples, ethh,
						 from_wan);
}

static __always_inline void copy_reversed_tuples(struct tuples_key *key,
						 struct tuples_key *dst)
{
	__builtin_memset(dst, 0, sizeof(*dst));
	dst->dip = key->sip;
	dst->sip = key->dip;
	dst->sport = key->dport;
	dst->dport = key->sport;
	dst->l4proto = key->l4proto;
}

static __always_inline bool pid_is_control_plane(struct __sk_buff *skb,
						 struct pid_pname **p)
{
	struct pid_pname *pid_pname;
	__u64 cookie = bpf_get_socket_cookie(skb);

	pid_pname = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	if (pid_pname) {
		pid_pname->last_seen_ns = bpf_ktime_get_ns();
		if (p) {
			// Assign.
			*p = pid_pname;
		}
		// Get tproxy pid and compare if they are equal.
		__u32 pid_tproxy;

		pid_tproxy = PARAM.control_plane_pid;
		if (!pid_tproxy) {
			bpf_printk("control_plane_pid is not set.");
			return false;
		}
		return pid_pname->pid == pid_tproxy;
	}
	if (p)
		*p = NULL;
	if (PARAM.dae_socket_mark && skb->mark == PARAM.dae_socket_mark)
		return true;
	if ((skb->mark & 0x100) == 0x100)
		return true;
	return false;
}

long control_plane_save_udp_traffic(struct tuples_key* key, struct routing_result *routing_result)
{
	__builtin_memset(&key->dip, 0, sizeof(key->dip));
	key->dport = 0;
	struct routing_result *existing = bpf_map_lookup_elem(&routing_tuples_map, key);
	if (existing) {
		existing->last_seen_ns = routing_result->last_seen_ns;
		return 0;
	}
	return bpf_map_update_elem(&routing_tuples_map, key, routing_result, BPF_ANY);
}

// Returns 0 to continue, 1 for direct, 2 for block.
u32 check_connectivity_map(struct routing_result *routing_result, struct __sk_buff *skb, u8 l4proto) {
	if (routing_result->outbound >= OUTBOUND_MUST_RULES)
		return 0;
	struct outbound_connectivity_query q = {
		.outbound = routing_result->outbound,
		.ipversion = skb->protocol == bpf_htons(ETH_P_IP) ? 4 : 6,
		.l4proto = l4proto
	};
	
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("outbound_connectivity_query: outbound: %u, ipversion: %u, l4proto: %u", q.outbound, q.ipversion, q.l4proto);
#endif

	__u32 *alive = bpf_map_lookup_elem(&outbound_connectivity_map, &q);
	if (!alive) {
		return 1;
	}
	return *alive;
}

// Routing and redirect the packet back.
static __always_inline int do_tproxy(struct __sk_buff *skb, bool is_wan, u32 link_h_len)
{
	__u8 *exited = bpf_map_lookup_elem(&exited_map, &zero_key);
	if (exited && *exited) {
		return TC_ACT_PIPE;
	}

	// Parse packet using scratch map + fast path.
	__u32 scratch_key = 0;
	struct parsed_packet *pkt =
		bpf_map_lookup_elem(&pkt_scratch_map, &scratch_key);

	if (!pkt)
		return TC_ACT_SHOT;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	int parse_ret = parse_packet(skb, link_h_len, pkt);
	if (parse_ret) {
		if (parse_ret < 0) {
			bpf_printk("do_tproxy parse error: %d, dropping", parse_ret);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	// Use parsed packet fields.
	struct ethhdr ethh = pkt->ethh;
	struct tuples tuples = pkt->tuples;
	struct tcphdr tcph = pkt->tcph;
	struct udphdr udph = pkt->udph;
	__u8 l4proto = pkt->l4proto;
	// listener_l4proto available via pkt->listener_l4proto

	if (l4proto == IPPROTO_ICMPV6)
		return TC_ACT_PIPE;

	// Backup for feature use.
	// 由于向helper function传递了skb, 一旦verifier无法推断出skb是否被修改, 则可能在访问skb时出现问题
	u16 protocol = skb->protocol;
	u32 ifindex = skb->ifindex;

	struct pid_pname *pid_pname = NULL;

	if (is_wan && pid_is_control_plane(skb, &pid_pname)) {
		// From control plane. Direct.
		return TC_ACT_PIPE;
	}

	bool isdns = tuples.five.dport == bpf_htons(53) && (l4proto == IPPROTO_UDP || l4proto == IPPROTO_TCP);

	if (l4proto == IPPROTO_TCP && !(tcph.syn && !tcph.ack)) {
		// Established TCP Connection.
		struct routing_result *routing_result =
			bpf_map_lookup_elem(&routing_tuples_map, &tuples.five);

		if (routing_result) {
			routing_result->last_seen_ns = bpf_ktime_get_ns();
			if (tcph.fin || tcph.rst)
				routing_result->state = STATE_CLOSING;
			goto control_plane;
		}

		// Non-proxy connections or previous connections.
		return TC_ACT_PIPE;
	}

	struct tuples_key udp_tuples_key;
	if (l4proto == IPPROTO_UDP) {
		udp_tuples_key = tuples.five;
		// Fast-path: per-flow full-5-tuple lookup. For DNS, zero
		// sport so all queries from the same IP share one entry.
		// Note: this assumes the rules configuration never uses
		// sport to differentiate routing for UDP 53.
		if (isdns)
			udp_tuples_key.sport = 0;
		struct routing_result *routing_result =
			bpf_map_lookup_elem(&routing_tuples_map, &udp_tuples_key);
		if (routing_result) {
			routing_result->last_seen_ns = bpf_ktime_get_ns();
			switch (routing_result->outbound) {
			case OUTBOUND_DIRECT:
				goto direct;
			case OUTBOUND_BLOCK:
				goto block;
			default:
				// Check connectivity — redirect based on alive state.
				if (!isdns) {
					switch (check_connectivity_map(routing_result, skb, l4proto)) {
					case 1:
						goto direct;
					case 2:
						goto block;
					}
				}
				if (control_plane_save_udp_traffic(&udp_tuples_key, routing_result)) {
					goto block;
				}
				goto control_plane;
			}
		}
	}

	// New Connection.
	// Fill route_params and call route().
	__u32 route_flag[8] = {};
	__be32 mac_be[4] = {
		0,
		0,
		bpf_htonl(((__u32)ethh.h_source[0] << 8) |
			  (__u32)ethh.h_source[1]),
		bpf_htonl(((__u32)ethh.h_source[2] << 24) |
			  ((__u32)ethh.h_source[3] << 16) |
			  ((__u32)ethh.h_source[4] << 8) |
			  (__u32)ethh.h_source[5]),
	};

	if (l4proto == IPPROTO_TCP) {
		route_flag[0] = L4ProtoType_TCP;
	} else {
		route_flag[0] = L4ProtoType_UDP;
		if (is_utp(skb, l4proto, 0)) {
			route_flag[0] |= (1 << 2);
		}
	}
	if (protocol == bpf_htons(ETH_P_IP))
		route_flag[1] = IpVersionType_4;
	else
		route_flag[1] = IpVersionType_6;
	if (pid_pname) {
		__builtin_memcpy(&route_flag[2],
				 pid_pname->pname,
				 TASK_COMM_LEN);
	}
	route_flag[6] = tuples.dscp;
	route_flag[7] = ifindex;

	// Route.
	__s64 s64_ret = route(route_flag,
			      l4proto == IPPROTO_TCP ? (const void *)&tcph :
						      (const void *)&udph,
			      tuples.five.sip.u6_addr32,
			      tuples.five.dip.u6_addr32,
			      mac_be);

	if (s64_ret < 0) {
		bpf_printk("shot routing: %d", s64_ret);
		return TC_ACT_SHOT;
	}

	// Fill routing result.
	struct routing_result routing_result = { 0 };

	routing_result.outbound = s64_ret;
	routing_result.mark = s64_ret >> 8;
	routing_result.must = (s64_ret >> 40) & 1;
	routing_result.dscp = tuples.dscp;
	routing_result.ifindex = ifindex;
	__builtin_memcpy(routing_result.mac, ethh.h_source,
			 sizeof(routing_result.mac));
	routing_result.last_seen_ns = bpf_ktime_get_ns();

	if (l4proto == IPPROTO_UDP) {
		bpf_map_update_elem(&routing_tuples_map, &udp_tuples_key,
					&routing_result, BPF_ANY);
	}

#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
	if (is_wan) {
		if (l4proto == IPPROTO_TCP) {
			bpf_printk("tcp(wan): outbound: %u, target: %pI6:%u",
				   routing_result.outbound, tuples.five.dip.u6_addr32,
				bpf_ntohs(tuples.five.dport));
		} else {
			bpf_printk("udp(wan): outbound: %u, target: %pI6:%u",
				   routing_result.outbound, tuples.five.dip.u6_addr32,
				bpf_ntohs(tuples.five.dport));
		}
	} else {
		if (l4proto == IPPROTO_TCP) {
			bpf_printk("tcp(lan): outbound: %u, target: %pI6:%u",
				   routing_result.outbound, tuples.five.dip.u6_addr32,
				bpf_ntohs(tuples.five.dport));
		} else {
			bpf_printk("udp(lan): outbound: %u, target: %pI6:%u",
				   routing_result.outbound, tuples.five.dip.u6_addr32,
				bpf_ntohs(tuples.five.dport));
		}
	}
#endif

	// Direct / Block.
	switch (routing_result.outbound) {
	case OUTBOUND_DIRECT:
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("GO OUTBOUND_DIRECT");
#endif
		goto direct;
	case OUTBOUND_BLOCK:
#if defined(__DEBUG_ROUTING) || defined(__PRINT_ROUTING_RESULT)
		bpf_printk("SHOT OUTBOUND_BLOCK");
#endif
		goto block;
	}

	if (!isdns) {
		// Check connectivity — redirect based on alive state.

		switch (check_connectivity_map(&routing_result, skb, l4proto)) {
		case 1:
			goto direct;
		case 2:
			goto block;
		}
	}

	// Only proxy traffic should be saved.
	long ret;
	if (l4proto == IPPROTO_UDP) {
		ret = control_plane_save_udp_traffic(&udp_tuples_key, &routing_result);
	} else {
		ret = bpf_map_update_elem(&routing_tuples_map, &tuples.five, &routing_result, BPF_ANY);
	}
	if (ret) {
		bpf_printk("shot save routing result: %d", s64_ret);
		return TC_ACT_SHOT;
	}

control_plane:
	// Assign to control plane.
	// Set cb[] before prep so dae0peer_ingress can filter on TPROXY_MARK.
	skb->cb[0] = TPROXY_MARK;
	skb->cb[1] = pkt->listener_l4proto;
	prep_redirect_to_control_plane(skb, link_h_len, &tuples, &ethh, is_wan);
	// lan_ingress is a tc ingress hook where bpf_redirect_peer is valid;
	// wan_egress is a tc egress hook where it is not.
	if (is_wan)
		return redirect_to_control_plane_egress();
	return redirect_to_control_plane_ingress();

direct:
	return TC_ACT_PIPE;

block:
	return TC_ACT_SHOT;
}

static __always_inline int do_lan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return TC_ACT_SHOT;

	int ret = parse_transport(skb, link_h_len, ctx);
	if (ret) {
		// Negative: error - drop; Positive: unsupported protocol - pass through
		if (ret < 0) {
			bpf_printk("parse_transport error: %d, dropping", ret);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	if (skb->ingress_ifindex == NOWHERE_IFINDEX &&  // Only drop NDP_REDIRECT packets from localhost
		ctx->l4proto == IPPROTO_ICMPV6 && ctx->icmp6h.icmp6_type == NDP_REDIRECT) {
		// REDIRECT (NDP)
		return TC_ACT_SHOT;
	}

	return TC_ACT_PIPE;
}

SEC("tc/lan_egress_l2")
int lan_egress_l2(struct __sk_buff *skb)
{
	return do_lan_egress(skb, ETH_HLEN);
}

SEC("tc/lan_egress_l3")
int lan_egress_l3(struct __sk_buff *skb)
{
	return do_lan_egress(skb, 0);
}

SEC("tc/lan_ingress_l2")
int lan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy(skb, false, ETH_HLEN);
}

SEC("tc/lan_ingress_l3")
int lan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy(skb, false, 0);
}

static __always_inline int do_tproxy_wan_ingress(struct __sk_buff *skb, u32 link_h_len)
{
	__u32 scratch_key = 0;
	struct parse_transport_ctx *ctx =
		bpf_map_lookup_elem(&parse_ctx_scratch_map, &scratch_key);

	if (!ctx)
		return TC_ACT_SHOT;

	int ret = parse_transport(skb, link_h_len, ctx);
	if (ret) {
		// Negative: error - drop; Positive: unsupported protocol - pass through
		if (ret < 0) {
			bpf_printk("parse_transport error: %d, dropping", ret);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	return TC_ACT_PIPE;
}

SEC("tc/wan_ingress_l2")
int tproxy_wan_ingress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_ingress(skb, ETH_HLEN);
}

SEC("tc/wan_ingress_l3")
int tproxy_wan_ingress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_ingress(skb, 0);
}

// We cannot modify the dest address here.
// So we redirect to dae0, using ingress path in dae0peer.
static __always_inline int do_tproxy_wan_egress(struct __sk_buff *skb, u32 link_h_len)
{
	// Skip packets not from localhost.
	if (skb->ingress_ifindex != NOWHERE_IFINDEX)
		return TC_ACT_OK;

	return do_tproxy(skb, true, link_h_len);
}

SEC("tc/wan_egress_l2")
int tproxy_wan_egress_l2(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, ETH_HLEN);
}

SEC("tc/wan_egress_l3")
int tproxy_wan_egress_l3(struct __sk_buff *skb)
{
	return do_tproxy_wan_egress(skb, 0);
}

// Proxy traffic.
SEC("tc/dae0peer_ingress")
int tproxy_dae0peer_ingress(struct __sk_buff *skb)
{
	// Only packets redirected from wan_egress or lan_ingress have this cb mark.
	if (skb->cb[0] != TPROXY_MARK)
		return TC_ACT_SHOT;

	/*
   * ip rule add fwmark 0x8000000/0x8000000 table 2023
   * ip route add local default dev lo table 2023
   * ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route add local default dev lo table 2023

   * ip rule del fwmark 0x8000000/0x8000000 table 2023
   * ip route del local default dev lo table 2023
   * ip -6 rule del fwmark 0x8000000/0x8000000 table 2023
   * ip -6 route del local default dev lo table 2023
   */
	// TODO: 直接redirect到lo?
	skb->mark = TPROXY_MARK;
	bpf_skb_change_type(skb, PACKET_HOST);

	/* l4proto is stored in skb->cb[1] only for UDP and new TCP. As for
   * established TCP, kernel can take care of socket lookup, so just
   * return them to stack without calling bpf_sk_assign.
   */
	__u8 l4proto = skb->cb[1];

	if (l4proto != 0)
		assign_listener(skb, l4proto);
	return TC_ACT_OK;
}

// load_redirect_tuple_fast returns this code when it cannot safely parse via
// direct packet access and should fall back to bpf_skb_load_bytes.
#define LOAD_REDIRECT_TUPLE_FALLBACK 2

static __always_inline int
load_redirect_tuple_fast(struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	void *data, *data_end;

	// Pull header data to linear region for direct access.
	// 128 bytes is enough for: ethhdr(14) + iphdr(40) + addresses.
#define REDIRECT_PULL_SIZE 128
	if (bpf_skb_pull_data(skb, REDIRECT_PULL_SIZE))
		return LOAD_REDIRECT_TUPLE_FALLBACK;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return LOAD_REDIRECT_TUPLE_FALLBACK;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + ETH_HLEN;

		if ((void *)(iph + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		// Use IPv4-mapped IPv6 format with ffff marker to match insert side
		redirect_tuple->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->sip.u6_addr32[3] = iph->daddr;
		redirect_tuple->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		redirect_tuple->dip.u6_addr32[3] = iph->saddr;
		return 0;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6h = data + ETH_HLEN;

		if ((void *)(ipv6h + 1) > data_end)
			return LOAD_REDIRECT_TUPLE_FALLBACK;
		__builtin_memcpy(&redirect_tuple->sip, &ipv6h->daddr,
				 sizeof(redirect_tuple->sip));
		__builtin_memcpy(&redirect_tuple->dip, &ipv6h->saddr,
				 sizeof(redirect_tuple->dip));
		return 0;
	}
	return 1;
}

static __always_inline int
load_redirect_tuple_slow(struct __sk_buff *skb,
			 struct redirect_tuple *redirect_tuple)
{
	int ret;

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		// Set ffff marker first for IPv4-mapped IPv6 format
		__u32 ffff_marker = bpf_htonl(0x0000ffff);

		redirect_tuple->sip.u6_addr32[2] = ffff_marker;
		redirect_tuple->dip.u6_addr32[2] = ffff_marker;

		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct iphdr, daddr),
					 &redirect_tuple->sip.u6_addr32[3],
					 sizeof(redirect_tuple->sip.u6_addr32[3]));
		if (ret)
			return ret;
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct iphdr, saddr),
					 &redirect_tuple->dip.u6_addr32[3],
					 sizeof(redirect_tuple->dip.u6_addr32[3]));
		if (ret)
			return ret;
		return 0;
	}
	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct ipv6hdr, daddr),
					 &redirect_tuple->sip,
					 sizeof(redirect_tuple->sip));
		if (ret)
			return ret;
		ret = bpf_skb_load_bytes(skb,
					 ETH_HLEN + offsetof(struct ipv6hdr, saddr),
					 &redirect_tuple->dip,
					 sizeof(redirect_tuple->dip));
		if (ret)
			return ret;
		return 0;
	}
	return 1;
}

static __always_inline int
load_redirect_tuple(struct __sk_buff *skb,
		    struct redirect_tuple *redirect_tuple)
{
	int ret = load_redirect_tuple_fast(skb, redirect_tuple);

	if (ret == LOAD_REDIRECT_TUPLE_FALLBACK)
		return load_redirect_tuple_slow(skb, redirect_tuple);
	return ret;
}

// Reply traffic.
SEC("tc/dae0_ingress")
int tproxy_dae0_ingress(struct __sk_buff *skb)
{
	struct redirect_tuple redirect_tuple = {};
	int ret;

	ret = load_redirect_tuple(skb, &redirect_tuple);
	if (ret)
		return TC_ACT_OK;
	struct redirect_entry *redirect_entry =
		bpf_map_lookup_elem(&redirect_track, &redirect_tuple);

	if (!redirect_entry)
		return TC_ACT_OK;

	redirect_entry->last_seen_ns = bpf_ktime_get_ns();

	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source),
			    redirect_entry->dmac, sizeof(redirect_entry->dmac),
			    0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest),
			    redirect_entry->smac, sizeof(redirect_entry->smac),
			    0);
	__u32 type = redirect_entry->from_wan ? PACKET_HOST : PACKET_OTHERHOST;

	bpf_skb_change_type(skb, type);
	__u64 flags = redirect_entry->from_wan ? BPF_F_INGRESS : 0;

	return bpf_redirect(redirect_entry->ifindex, flags);
}

struct get_real_comm_ctx {
	char *arg_buf;
	u8 l;
};

static int __noinline get_real_comm_loop_cb(__u32 index, void *data)
{
	/*
	* For string like: /usr/lib/sddm/sddm-helper --socket /tmp/sddm-auth1
	* We extract "sddm-helper" from it.
	*/
	struct get_real_comm_ctx *ctx = (struct get_real_comm_ctx *)data;

	if (index >= MAX_ARG_LEN) // always false, just to make verifier happy
		return 1;
	if (unlikely(ctx->arg_buf[index] == '/'))
		ctx->l = index + 1;
	if (unlikely(ctx->arg_buf[index] == ' ' ||
		     ctx->arg_buf[index] == '\0')) {
		// Write to dst.
		ctx->arg_buf[index] = '\0';
		return 1;
	}
	return 0;
}

/// Parse command line arguments to get the real command name and tgid.
static __always_inline int get_pid_pname(struct pid_pname *pid_pname)
{
	int ret;
	// Get pointer to args string.
	struct task_struct *task = (void *)bpf_get_current_task();
	char *args = (void *)BPF_CORE_READ(task, mm, arg_start);

	// Read args to buffer.
	char arg_buf[MAX_ARG_LEN]; // Allocate it out of ctx to pass CO-RE
	struct get_real_comm_ctx ctx = {};

	ctx.arg_buf = arg_buf;
	ret = bpf_core_read_user_str(arg_buf, MAX_ARG_LEN, args);
	if (unlikely(ret < 0)) {
		bpf_printk(
			"failed to read process name: bpf_core_read_user_str: %d",
			ret);
		return ret;
	}

	// Find range of command name.
	ret = bpf_loop(MAX_ARG_LEN, get_real_comm_loop_cb, &ctx, 0);
	if (unlikely(ret < 0))
		return ret;

	u8 offset = ctx.l;

	for (u8 i = 0; i < TASK_COMM_LEN; i++) {
		if (offset + i < MAX_ARG_LEN && arg_buf[offset + i] != '\0') {
			pid_pname->pname[i] = arg_buf[offset + i];
		} else {
			pid_pname->pname[i] = '\0';
			break;
		}
	}

	// Pupulate tgid
	ret = bpf_core_read(&pid_pname->pid, sizeof(pid_pname->pid),
			    &task->tgid);
	if (unlikely(ret < 0)) {
		bpf_printk("failed to read pid: %d", ret);
		return ret;
	}
	return 0;
}

static __always_inline int _update_map_elem_by_cookie(const __u64 cookie,
						      struct pid_pname *val)
{
	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return -EINVAL;
	}
	struct pid_pname *existing = bpf_map_lookup_elem(&cookie_pid_map, &cookie);
	if (existing) {
		// Cookie to pid mapping already exists.
		existing->last_seen_ns = bpf_ktime_get_ns();
		return 0;
	}

	int ret;

	ret = get_pid_pname(val);
	if (ret)
		return ret;

	// Update map.
	ret = bpf_map_update_elem(&cookie_pid_map, &cookie, val, BPF_ANY);
	if (unlikely(ret)) {
		// bpf_printk("setup_mapping_from_sk: failed update map: %d", ret);
		return ret;
	}

#ifdef __PRINT_SETUP_PROCESS_CONNNECTION
	bpf_printk("setup_mapping: %llu -> %s (%d)", cookie, val.pname,
		   val.pid);
#endif
	return 0;
}

static __always_inline int update_map_elem_by_cookie(const __u64 cookie)
{
	int ret;
	struct pid_pname val = {};

	ret = _update_map_elem_by_cookie(cookie, &val);
	if (ret) {
		// Fallback to only write pid to avoid loop due to packets sent by dae.
		val.last_seen_ns = bpf_ktime_get_ns();
		val.pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&cookie_pid_map, &cookie, &val, BPF_ANY);
		return ret;
	}
	return 0;
}

// Create cookie to pid, pname mapping.
SEC("cgroup/sock_create")
int tproxy_wan_cg_sock_create(struct bpf_sock *sk)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(sk));
	return 1;
}

// Remove cookie to pid, pname mapping.
SEC("cgroup/sock_release")
int tproxy_wan_cg_sock_release(struct bpf_sock *sk)
{
	__u64 cookie = bpf_get_socket_cookie(sk);

	if (unlikely(!cookie)) {
		bpf_printk("zero cookie");
		return 1;
	}
	bpf_map_delete_elem(&cookie_pid_map, &cookie);
	return 1;
}

SEC("cgroup/connect4")
int tproxy_wan_cg_connect4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/connect6")
int tproxy_wan_cg_connect6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg4")
int tproxy_wan_cg_sendmsg4(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg6")
int tproxy_wan_cg_sendmsg6(struct bpf_sock_addr *ctx)
{
	update_map_elem_by_cookie(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("sockops")
int local_tcp_sockops(struct bpf_sock_ops *skops)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 pid = BPF_CORE_READ(task, pid);

	/* Only local TCP connection has non-zero pids. */
	if (pid == 0)
		return 0;

	struct tuples_key tuple = {};

	tuple.l4proto = IPPROTO_TCP;
	tuple.sport = bpf_htonl(skops->local_port) >> 16;
	tuple.dport = skops->remote_port >> 16;
	if (skops->family == AF_INET) {
		tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuple.sip.u6_addr32[3] = skops->local_ip4;
		tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		tuple.dip.u6_addr32[3] = skops->remote_ip4;
	} else if (skops->family == AF_INET6) {
		tuple.sip.u6_addr32[3] = skops->local_ip6[3];
		tuple.sip.u6_addr32[2] = skops->local_ip6[2];
		tuple.sip.u6_addr32[1] = skops->local_ip6[1];
		tuple.sip.u6_addr32[0] = skops->local_ip6[0];
		tuple.dip.u6_addr32[3] = skops->remote_ip6[3];
		tuple.dip.u6_addr32[2] = skops->remote_ip6[2];
		tuple.dip.u6_addr32[1] = skops->remote_ip6[1];
		tuple.dip.u6_addr32[0] = skops->remote_ip6[0];
	} else {
		return 0;
	}

	switch (skops->op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // dae sockets
	{
		struct tuples_key rev_tuple = {};

		copy_reversed_tuples(&tuple, &rev_tuple);

		struct routing_result *routing_result;

		routing_result =
			bpf_map_lookup_elem(&routing_tuples_map, &rev_tuple);
		if (!routing_result || !routing_result->pid)
			break;

		if (!bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY))
			bpf_printk("fast_sock added: %pI4:%lu -> %pI4:%lu",
				   &tuple.sip.u6_addr32[3],
				   bpf_ntohs(tuple.sport),
				   &tuple.dip.u6_addr32[3],
				   bpf_ntohs(tuple.dport));
		break;
	}

	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // local client sockets
	{
		struct routing_result *routing_result;

		routing_result =
			bpf_map_lookup_elem(&routing_tuples_map, &tuple);
		if (!routing_result || !routing_result->pid)
			break;

		if (!bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY))
			bpf_printk("fast_sock added: %pI4:%lu -> %pI4:%lu",
				   &tuple.sip.u6_addr32[3],
				   bpf_ntohs(tuple.sport),
				   &tuple.dip.u6_addr32[3],
				   bpf_ntohs(tuple.dport));
		break;
	}

	default:
		break;
	}

	return 0;
}

SEC("sk_msg/fast_redirect")
int sk_msg_fast_redirect(struct sk_msg_md *msg)
{
	struct tuples_key rev_tuple = {};

	rev_tuple.l4proto = IPPROTO_TCP;
	rev_tuple.sport = msg->remote_port >> 16;
	rev_tuple.dport = bpf_htonl(msg->local_port) >> 16;
	if (msg->family == AF_INET) {
		rev_tuple.sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		rev_tuple.sip.u6_addr32[3] = msg->remote_ip4;
		rev_tuple.dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		rev_tuple.dip.u6_addr32[3] = msg->local_ip4;
	} else if (msg->family == AF_INET6) {
		rev_tuple.sip.u6_addr32[3] = msg->remote_ip6[3];
		rev_tuple.sip.u6_addr32[2] = msg->remote_ip6[2];
		rev_tuple.sip.u6_addr32[1] = msg->remote_ip6[1];
		rev_tuple.sip.u6_addr32[0] = msg->remote_ip6[0];
		rev_tuple.dip.u6_addr32[3] = msg->local_ip6[3];
		rev_tuple.dip.u6_addr32[2] = msg->local_ip6[2];
		rev_tuple.dip.u6_addr32[1] = msg->local_ip6[1];
		rev_tuple.dip.u6_addr32[0] = msg->local_ip6[0];
	} else {
		return SK_PASS;
	}

	if (bpf_msg_redirect_hash(msg, &fast_sock, &rev_tuple, BPF_F_INGRESS) ==
	    SK_PASS)
		bpf_printk("tcp fast redirect: %pI4:%lu -> %pI4:%lu",
			   &rev_tuple.sip.u6_addr32[3],
			   bpf_ntohs(rev_tuple.sport),
			   &rev_tuple.dip.u6_addr32[3],
			   bpf_ntohs(rev_tuple.dport));

	return SK_PASS;
}


SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    /* get PID and TID of exiting thread/process */
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = id;

    /* ignore thread exits */
    if (pid != tid)
		return 0;

	if (pid == PARAM.control_plane_pid)
		bpf_map_update_elem(&exited_map, &zero_key, &one_key, BPF_ANY);
	return 0;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
