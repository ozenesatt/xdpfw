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
	STAT_MAX,
};

/* Her kural icin kac paket eslesti */
struct rule_stat {
	__u64 hits;
};

/*
 * Port blacklist anahtari.
 *
 * DIKKAT: BPF hash map anahtarlari BAYT BAYT karsilastirilir.
 * Derleyici struct'i 4 bayta hizalar; 4. bayt tanimsiz kalirsa
 * icindeki cop yuzunden lookup asla tutmaz.
 * Bu yuzden pad alani ACIKCA tanimli ve her kullanimdan once
 * struct memset ile sifirlaniyor.
 */
struct port_key {
	__u16 port;   /* network byte order */
	__u8  proto;  /* IPPROTO_TCP = 6, IPPROTO_UDP = 17 */
	__u8  pad;    /* her zaman 0 */
};

#endif /* __XDPFW_H */
