// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
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

static int block_ip(int map_fd, const char *ipstr)
{
	struct rule_stat val = {};
	struct in_addr addr;
	__u32 key;

	if (inet_pton(AF_INET, ipstr, &addr) != 1) {
		fprintf(stderr, "Gecersiz IPv4 adresi: %s\n", ipstr);
		return -1;
	}

	/* addr.s_addr network byte order; BPF de cevirmeden kullaniyor */
	key = addr.s_addr;

	if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)) {
		fprintf(stderr, "Map'e yazilamadi: %s\n", strerror(errno));
		return -1;
	}
	printf("Engellendi (IP): %s\n", ipstr);
	return 0;
}

/* "tcp:9999" veya "udp:53" formatini isler */
static int block_port(int map_fd, const char *spec)
{
	struct rule_stat val = {};
	struct port_key key;
	const char *iki_nokta;
	int port;
	__u8 proto;

	iki_nokta = strchr(spec, ':');
	if (!iki_nokta) {
		fprintf(stderr, "Gecersiz kural: %s (ornek: tcp:8080)\n", spec);
		return -1;
	}

	if (!strncmp(spec, "tcp:", 4))
		proto = IPPROTO_TCP;
	else if (!strncmp(spec, "udp:", 4))
		proto = IPPROTO_UDP;
	else {
		fprintf(stderr, "Protokol 'tcp' veya 'udp' olmali: %s\n", spec);
		return -1;
	}

	port = atoi(iki_nokta + 1);
	if (port < 1 || port > 65535) {
		fprintf(stderr, "Gecersiz port: %s\n", spec);
		return -1;
	}

	/* KRITIK: padding dahil tum struct sifirlanmali */
	memset(&key, 0, sizeof(key));
	key.port  = htons((__u16)port);   /* network byte order */
	key.proto = proto;

	if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)) {
		fprintf(stderr, "Map'e yazilamadi: %s\n", strerror(errno));
		return -1;
	}
	printf("Engellendi (port): %s\n", spec);
	return 0;
}

static void list_rules(int ip_fd, int port_fd)
{
	char buf[INET_ADDRSTRLEN];
	struct rule_stat val;
	int bos = 1;

	printf("\nKurallar:\n");

	{
		__u32 key, next_key, *pk = NULL;

		while (bpf_map_get_next_key(ip_fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(ip_fd, &key, &val) == 0) {
				inet_ntop(AF_INET, &key, buf, sizeof(buf));
				printf("  ip   %-16s eslesme=%llu\n", buf,
				       (unsigned long long)val.hits);
				bos = 0;
			}
			pk = &key;
		}
	}

	{
		struct port_key key, next_key, *pk = NULL;

		while (bpf_map_get_next_key(port_fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(port_fd, &key, &val) == 0) {
				printf("  %-4s %-16u eslesme=%llu\n",
				       key.proto == IPPROTO_TCP ? "tcp" : "udp",
				       ntohs(key.port),
				       (unsigned long long)val.hits);
				bos = 0;
			}
			pk = &key;
		}
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
	int ifindex, ncpu, stats_fd, ip_fd, port_fd, err = 0;
	int first = 1, i;
	__u32 k;

	if (argc < 2) {
		fprintf(stderr,
			"Kullanim: %s <arayuz> [kural ...]\n"
			"Kural formatlari:\n"
			"  10.10.0.2    kaynak IP engelle\n"
			"  tcp:9999     hedef TCP portu engelle\n"
			"  udp:53       hedef UDP portu engelle\n"
			"\nOrnek: sudo %s veth0 tcp:9999 10.10.0.5\n",
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
	ip_fd    = bpf_map__fd(skel->maps.blocked_ips);
	port_fd  = bpf_map__fd(skel->maps.blocked_ports);

	/* Komut satirindaki kurallari isle */
	for (i = 2; i < argc; i++) {
		if (strchr(argv[i], ':'))
			block_port(port_fd, argv[i]);
		else
			block_ip(ip_fd, argv[i]);
	}

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

		list_rules(ip_fd, port_fd);
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
