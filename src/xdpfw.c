// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdpfw.h"
#include "xdpfw.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !getenv("XDPFW_DEBUG"))
		return 0;
	return vfprintf(stderr, fmt, args);
}

static const char *stat_names[STAT_MAX] = {
	[STAT_TOTAL]   = "Toplam paket",
	[STAT_TCP]     = "TCP",
	[STAT_UDP]     = "UDP",
	[STAT_ICMP]    = "ICMP",
	[STAT_OTHER]   = "Diger",
	[STAT_PASSED]  = "PASS (gecen)",
	[STAT_DROPPED] = "DROP (engellenen)",
};

/* Blacklist'e IP ekle. Donus: 0 basarili */
static int block_ip(int map_fd, const char *ipstr)
{
	struct rule_stat val = {};
	struct in_addr addr;
	__u32 key;

	if (inet_pton(AF_INET, ipstr, &addr) != 1) {
		fprintf(stderr, "Gecersiz IPv4 adresi: %s\n", ipstr);
		return -1;
	}

	/* addr.s_addr zaten network byte order. BPF tarafi da
	 * ip->saddr'i cevirmeden kullaniyor -> uyumlu. */
	key = addr.s_addr;

	if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)) {
		fprintf(stderr, "Map'e yazilamadi: %s\n", strerror(errno));
		return -1;
	}
	printf("Engellendi: %s\n", ipstr);
	return 0;
}

/* Kural listesini ve eslesme sayilarini bas */
static void list_rules(int map_fd)
{
	char buf[INET_ADDRSTRLEN];
	struct rule_stat val;
	__u32 key, next_key;
	__u32 *pk = NULL;
	int bos = 1;

	printf("\nEngellenen IP'ler:\n");
	while (bpf_map_get_next_key(map_fd, pk, &next_key) == 0) {
		key = next_key;
		if (bpf_map_lookup_elem(map_fd, &key, &val) == 0) {
			inet_ntop(AF_INET, &key, buf, sizeof(buf));
			printf("  %-16s eslesme=%llu\n", buf,
			       (unsigned long long)val.hits);
			bos = 0;
		}
		pk = &key;
	}
	if (bos)
		printf("  (kural yok)\n");
}

int main(int argc, char **argv)
{
	struct xdpfw_bpf *skel;
	struct bpf_link *link = NULL;
	__u64 cur[STAT_MAX], prev[STAT_MAX] = {};
	__u64 *percpu = NULL;
	int ifindex, ncpu, stats_fd, bl_fd, err = 0;
	int first = 1, i;
	__u32 k;

	if (argc < 2) {
		fprintf(stderr,
			"Kullanim: %s <arayuz> [engellenecek-ip ...]\n"
			"Ornek:   sudo %s veth0 10.10.0.2\n",
			argv[0], argv[0]);
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Arayuz bulunamadi: %s\n", argv[1]);
		return 1;
	}

	libbpf_set_print(print_fn);

	skel = xdpfw_bpf__open();
	if (!skel)
		return 1;

	err = xdpfw_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Yukleme basarisiz (%d). Detay: XDPFW_DEBUG=1\n", err);
		goto cleanup;
	}

	stats_fd = bpf_map__fd(skel->maps.stats);
	bl_fd    = bpf_map__fd(skel->maps.blocked_ips);

	/* Komut satirindaki IP'leri blacklist'e ekle */
	for (i = 2; i < argc; i++)
		block_ip(bl_fd, argv[i]);

	link = bpf_program__attach_xdp(skel->progs.xdp_fw, ifindex);
	if (!link) {
		err = -errno;
		fprintf(stderr, "XDP attach basarisiz: %s\n", strerror(errno));
		goto cleanup;
	}

	ncpu = libbpf_num_possible_cpus();
	percpu = calloc(ncpu, sizeof(__u64));
	if (!percpu) {
		err = -1;
		goto cleanup;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	while (!stop) {
		for (k = 0; k < STAT_MAX; k++) {
			__u64 sum = 0;

			if (bpf_map_lookup_elem(stats_fd, &k, percpu) == 0)
				for (i = 0; i < ncpu; i++)
					sum += percpu[i];
			cur[k] = sum;
		}

		printf("\033[2J\033[H");
		printf("XDP firewall - %s (%d CPU) - Ctrl+C ile cik\n\n", argv[1], ncpu);
		printf("%-18s %14s %12s\n", "SAYAC", "TOPLAM", "PAKET/SN");
		printf("---------------------------------------------\n");
		for (k = 0; k < STAT_MAX; k++)
			printf("%-18s %14llu %12llu\n", stat_names[k],
			       (unsigned long long)cur[k],
			       (unsigned long long)(first ? 0 : cur[k] - prev[k]));

		list_rules(bl_fd);
		fflush(stdout);

		memcpy(prev, cur, sizeof(cur));
		first = 0;
		sleep(1);
	}

	printf("\nKaldiriliyor...\n");

cleanup:
	free(percpu);
	bpf_link__destroy(link);
	xdpfw_bpf__destroy(skel);
	return err ? 1 : 0;
}
