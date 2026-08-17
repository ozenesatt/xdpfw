/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __XDPFW_H
#define __XDPFW_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

enum stat_idx {
	STAT_TOTAL = 0,
	STAT_TCP,
	STAT_UDP,
	STAT_ICMP,
	STAT_OTHER,
	STAT_PASSED,
	STAT_DROPPED,
	STAT_DROP_IP,     /* IP kurali dusurdu */
	STAT_DROP_PORT,   /* port kurali dusurdu */
	STAT_MAX,
};

/* Drop sebepleri - ring buffer olayinda da kullaniliyor */
enum drop_reason {
	REASON_IP = 0,
	REASON_PORT,
};

struct rule_stat {
	__u64 hits;
};

/*
 * Port blacklist anahtari.
 * BPF hash map anahtarlari BAYT BAYT karsilastirilir; padding
 * sifirlanmazsa lookup tutmaz. pad acikca tanimli, memset zorunlu.
 */
struct port_key {
	__u16 port;   /* network byte order */
	__u8  proto;  /* IPPROTO_TCP = 6, IPPROTO_UDP = 17 */
	__u8  pad;    /* her zaman 0 */
};

/* Ring buffer ile userspace'e gonderilen drop olayi */
struct drop_event {
	__u64 ts;      /* bpf_ktime_get_ns() - boot'tan beri gecen ns */
	__u32 saddr;   /* kaynak IP, network byte order */
	__u16 dport;   /* hedef port, network byte order (0 = yok) */
	__u8  proto;
	__u8  reason;  /* enum drop_reason */
};

#endif /* __XDPFW_H */
