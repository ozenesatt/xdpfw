// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdpfw.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/*
 * CIDR blacklist (LPM_TRIE).
 * BPF_F_NO_PREALLOC zorunlu: trie dinamik buyur, onceden ayrilamaz.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1024);
	__type(key, struct lpm_key);
	__type(value, struct rule_stat);
} blocked_ips SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct port_key);
	__type(value, struct rule_stat);
} blocked_ports SEC(".maps");

/*
 * Ring buffer: kernel -> userspace olay akisi.
 * max_entries = tampon boyutu (bayt), 2'nin kuvveti ve sayfa boyutunun
 * kati olmali. 256 KB yaklasik 6500 olay tutar.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&stats, &idx);

	if (val)
		*val += 1;
}

/* Drop olayini ring buffer'a yaz */
static __always_inline void olay_gonder(__u32 saddr, __u16 dport,
					__u8 proto, __u8 reason)
{
	struct drop_event *e;

	/* reserve NULL donebilir (tampon dolu) - verifier kontrol istiyor */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts     = bpf_ktime_get_ns();
	e->saddr  = saddr;
	e->dport  = dport;
	e->proto  = proto;
	e->reason = reason;

	bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct rule_stat *rs;
	struct port_key pk;
	struct lpm_key lk;
	void *l4;
	__u32 ihl_bytes, saddr;
	__u16 dport = 0;

	bump(STAT_TOTAL);

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		bump(STAT_OTHER);
		bump(STAT_PASSED);
		return XDP_PASS;
	}

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	if (ip->ihl < 5)
		return XDP_PASS;
	ihl_bytes = ip->ihl * 4;

	l4 = (void *)ip + ihl_bytes;
	if (l4 > data_end)
		return XDP_PASS;

	/* --- KURAL 1: kaynak IP blacklist --- */
	saddr = ip->saddr;

	/* LPM lookup: prefixlen her zaman 32, kernel en uzun oneki bulur */
	__builtin_memset(&lk, 0, sizeof(lk));
	lk.prefixlen = 32;
	__builtin_memcpy(lk.data, &saddr, 4);

	rs = bpf_map_lookup_elem(&blocked_ips, &lk);
	if (rs) {
		__sync_fetch_and_add(&rs->hits, 1);
		bump(STAT_DROPPED);
		bump(STAT_DROP_IP);
		olay_gonder(saddr, 0, ip->protocol, REASON_IP);
		return XDP_DROP;
	}

	/* --- Protokol sayaci + hedef port --- */
	switch (ip->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcp = l4;

		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		dport = tcp->dest;
		bump(STAT_TCP);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udp = l4;

		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		dport = udp->dest;
		bump(STAT_UDP);
		break;
	}
	case IPPROTO_ICMP:
		bump(STAT_ICMP);
		break;
	default:
		bump(STAT_OTHER);
		break;
	}

	/* --- KURAL 2: hedef port blacklist --- */
	if (dport) {
		__builtin_memset(&pk, 0, sizeof(pk));
		pk.port  = dport;
		pk.proto = ip->protocol;

		rs = bpf_map_lookup_elem(&blocked_ports, &pk);
		if (rs) {
			__sync_fetch_and_add(&rs->hits, 1);
			bump(STAT_DROPPED);
			bump(STAT_DROP_PORT);
			olay_gonder(saddr, dport, ip->protocol, REASON_PORT);
			return XDP_DROP;
		}
	}

	bump(STAT_PASSED);
	return XDP_PASS;
}
