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
 * IP blacklist.
 * key   = kaynak IPv4 adresi (network byte order, cevrilmeden)
 * value = bu kural kac pakette eslesti
 * HASH paylasimli: CPU basina kopya yok, artis atomik olmali.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct rule_stat);
} blocked_ips SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&stats, &idx);

	if (val)
		*val += 1;
}

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct rule_stat *rs;
	__u32 ihl_bytes, saddr;

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

	if ((void *)ip + ihl_bytes > data_end)
		return XDP_PASS;

	/* --- KURAL: kaynak IP blacklist'te mi? ---
	 * saddr CEVRILMIYOR. Paketten network byte order geliyor,
	 * kullanici alani da inet_pton ile ayni sirada yaziyor.
	 */
	saddr = ip->saddr;
	rs = bpf_map_lookup_elem(&blocked_ips, &saddr);
	if (rs) {
		__sync_fetch_and_add(&rs->hits, 1);
		bump(STAT_DROPPED);
		return XDP_DROP;
	}

	switch (ip->protocol) {
	case IPPROTO_TCP:
		bump(STAT_TCP);
		break;
	case IPPROTO_UDP:
		bump(STAT_UDP);
		break;
	case IPPROTO_ICMP:
		bump(STAT_ICMP);
		break;
	default:
		bump(STAT_OTHER);
		break;
	}

	bump(STAT_PASSED);
	return XDP_PASS;
}
