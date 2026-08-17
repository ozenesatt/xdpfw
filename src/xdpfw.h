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

#endif /* __XDPFW_H */
