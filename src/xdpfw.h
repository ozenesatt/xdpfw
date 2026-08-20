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
	STAT_DROP_FLOW,   /* bilesik kural dusurdu */
	STAT_DROP_WL,     /* whitelist: izinli degil */
	STAT_MAX,
};


/* Calisma modu (config map'inde tutulur) */
enum fw_mode {
	MODE_BLACKLIST = 0,   /* varsayilan: listedekiler dusurulur */
	MODE_WHITELIST = 1,   /* listede OLMAYANLAR dusurulur */
};

/* config map indeksleri */
enum cfg_idx {
	CFG_MODE = 0,
	CFG_MAX,
};

/* Drop sebepleri - ring buffer olayinda da kullaniliyor */
enum drop_reason {
	REASON_IP = 0,
	REASON_PORT,
	REASON_FLOW,          /* bilesik kural */
	REASON_NOT_ALLOWED,   /* whitelist: izinli listede yok */
};


/*
 * LPM_TRIE anahtari (CIDR blacklist).
 *
 * prefixlen ILK alan ve __u32 olmak ZORUNDA - kernel boyle bekliyor.
 * data[] network byte order, IPv4 icin 4 bayt.
 *
 * Lookup'ta prefixlen = 32 verilir; kernel en uzun eslesen oneki bulur
 * (Longest Prefix Match). Bu sayede /32 tek adres engellemesi de calisir.
 */
struct lpm_key {
	__u32 prefixlen;   /* 0-32 */
	__u8  data[4];     /* IPv4, network byte order */
};

struct rule_stat {
	__u64 hits;
};


/*
 * Bilesik kural anahtari: kaynak IP + protokol + hedef port.
 *
 * Padding yine kritik - bayt bayt karsilastirma yapiliyor.
 * IP burada TAM ADRES (/32); CIDR desteklenmiyor cunku hash map
 * onek eslesmesi yapamaz, trie de port bilgisi tasiyamaz.
 */
struct flow_key {
	__u32 saddr;   /* network byte order */
	__u16 dport;   /* network byte order */
	__u8  proto;
	__u8  pad;     /* her zaman 0 */
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
