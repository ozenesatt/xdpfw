// SPDX-License-Identifier: GPL-2.0
/*
 * xdpfw - XDP firewall kullanici alani araci
 *
 * Tasarim: "load" komutu programi baglayip map'leri ve link'i bpffs'e
 * pinler, sonra cikar. Diger komutlar pinlenmis map'leri acarak calisir.
 * "unload" link pinini siler -> son referans gidince kernel programi
 * otomatik detach eder.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdpfw.h"
#include "xdpfw.skel.h"

#define PIN_DIR "/sys/fs/bpf/xdpfw"

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
	[STAT_DROPPED] = "DROP (toplam)",
	[STAT_DROP_IP] = "  - IP kurali",
	[STAT_DROP_PORT] = "  - port kurali",
};

/* Pinlenmis bir map'i ac */
static int open_pinned(const char *name)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path), PIN_DIR "/%s", name);
	fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr,
			"'%s' acilamadi: %s\n"
			"Program yuklu mu? 'sudo %s load <arayuz>' calistir.\n",
			path, strerror(errno), "./xdpfw");
	return fd;
}

/* ---------------------------------------------------------------- load */

static int cmd_load(const char *ifname)
{
	struct xdpfw_bpf *skel;
	char path[256];
	int ifindex, link_fd, err;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Arayuz bulunamadi: %s\n", ifname);
		return 1;
	}

	if (mkdir(PIN_DIR, 0700) && errno != EEXIST) {
		fprintf(stderr, "%s olusturulamadi: %s\n"
			"bpffs mount edili mi? 'sudo mount -t bpf bpf /sys/fs/bpf'\n",
			PIN_DIR, strerror(errno));
		return 1;
	}

	skel = xdpfw_bpf__open();
	if (!skel)
		return 1;

	/*
	 * Pin yolunu load'dan ONCE ayarliyoruz.
	 * libbpf: yol zaten varsa mevcut map'i yeniden kullanir,
	 *         yoksa map'i olusturup pinler.
	 */
	bpf_map__set_pin_path(skel->maps.stats, PIN_DIR "/stats");
	bpf_map__set_pin_path(skel->maps.blocked_ips, PIN_DIR "/blocked_ips");
	bpf_map__set_pin_path(skel->maps.blocked_ports, PIN_DIR "/blocked_ports");
	bpf_map__set_pin_path(skel->maps.events, PIN_DIR "/events");

	err = xdpfw_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Yukleme basarisiz (%d). Detay: XDPFW_DEBUG=1\n", err);
		goto out;
	}

	link_fd = bpf_link_create(bpf_program__fd(skel->progs.xdp_fw),
				  ifindex, BPF_XDP, NULL);
	if (link_fd < 0) {
		fprintf(stderr, "XDP attach basarisiz: %s\n", strerror(errno));
		err = 1;
		goto out;
	}

	/* Link'i pinle: proses cikinca program detach olmasin */
	snprintf(path, sizeof(path), PIN_DIR "/link_%s", ifname);
	unlink(path);
	if (bpf_obj_pin(link_fd, path)) {
		fprintf(stderr, "Link pinlenemedi: %s\n", strerror(errno));
		close(link_fd);
		err = 1;
		goto out;
	}
	close(link_fd);

	printf("XDP programi '%s' arayuzune baglandi.\n", ifname);
	printf("Kural ekle : sudo ./xdpfw block-ip 10.10.0.2\n");
	printf("Istatistik : sudo ./xdpfw stats\n");
	err = 0;
out:
	xdpfw_bpf__destroy(skel);
	return err;
}

/* -------------------------------------------------------------- unload */

static int cmd_unload(const char *ifname)
{
	char path[256];

	snprintf(path, sizeof(path), PIN_DIR "/link_%s", ifname);
	if (unlink(path)) {
		fprintf(stderr, "%s silinemedi: %s\n", path, strerror(errno));
		return 1;
	}
	printf("'%s' arayuzunden XDP programi kaldirildi.\n", ifname);
	printf("Map'leri de temizlemek icin: sudo rm -rf %s\n", PIN_DIR);
	return 0;
}

/* --------------------------------------------------------------- stats */

static int cmd_stats(int interval)
{
	__u64 cur[STAT_MAX], prev[STAT_MAX] = {};
	__u64 *percpu;
	int fd, ncpu, i, first = 1;
	__u32 k;

	fd = open_pinned("stats");
	if (fd < 0)
		return 1;

	ncpu = libbpf_num_possible_cpus();
	percpu = calloc(ncpu, sizeof(__u64));
	if (!percpu)
		return 1;

	signal(SIGINT, on_signal);

	while (!stop) {
		for (k = 0; k < STAT_MAX; k++) {
			__u64 sum = 0;

			if (bpf_map_lookup_elem(fd, &k, percpu) == 0)
				for (i = 0; i < ncpu; i++)
					sum += percpu[i];
			cur[k] = sum;
		}

		printf("\033[2J\033[H");
		printf("XDP firewall - canli istatistik (%d CPU) - Ctrl+C\n\n", ncpu);
		printf("%-18s %14s %12s\n", "SAYAC", "TOPLAM", "PAKET/SN");
		printf("---------------------------------------------\n");
		for (k = 0; k < STAT_MAX; k++)
			printf("%-18s %14llu %12llu\n", stat_names[k],
			       (unsigned long long)cur[k],
			       (unsigned long long)(first ? 0 : (cur[k] - prev[k]) / interval));
		fflush(stdout);

		memcpy(prev, cur, sizeof(cur));
		first = 0;
		sleep(interval);
	}

	free(percpu);
	close(fd);
	return 0;
}

/* ------------------------------------------------------------ kurallar */

static int cmd_ip(const char *spec, int ekle)
{
	struct rule_stat val = {};
	struct lpm_key key;
	struct in_addr addr;
	char ipstr[64];
	char *egik;
	int fd, err, prefixlen = 32;

	/* "10.0.0.0/8" veya "10.10.0.2" ayristir */
	snprintf(ipstr, sizeof(ipstr), "%s", spec);
	egik = strchr(ipstr, '/');
	if (egik) {
		*egik = '\0';
		prefixlen = atoi(egik + 1);
		if (prefixlen < 0 || prefixlen > 32) {
			fprintf(stderr, "Gecersiz prefix uzunlugu: %s\n", spec);
			return 1;
		}
	}

	if (inet_pton(AF_INET, ipstr, &addr) != 1) {
		fprintf(stderr, "Gecersiz IPv4 adresi: %s\n", ipstr);
		return 1;
	}

	fd = open_pinned("blocked_ips");
	if (fd < 0)
		return 1;

	memset(&key, 0, sizeof(key));
	key.prefixlen = (__u32)prefixlen;
	memcpy(key.data, &addr.s_addr, 4);   /* network byte order */

	if (ekle)
		err = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
	else
		err = bpf_map_delete_elem(fd, &key);

	if (err)
		fprintf(stderr, "Islem basarisiz: %s\n", strerror(errno));
	else
		printf("%s/%d %s\n", ipstr, prefixlen,
		       ekle ? "engellendi." : "engeli kaldirildi.");

	close(fd);
	return err ? 1 : 0;
}

static int cmd_port(const char *proto_s, const char *port_s, int ekle)
{
	struct rule_stat val = {};
	struct port_key key;
	int fd, err, port;
	__u8 proto;

	if (!strcmp(proto_s, "tcp"))
		proto = IPPROTO_TCP;
	else if (!strcmp(proto_s, "udp"))
		proto = IPPROTO_UDP;
	else {
		fprintf(stderr, "Protokol 'tcp' veya 'udp' olmali.\n");
		return 1;
	}

	port = atoi(port_s);
	if (port < 1 || port > 65535) {
		fprintf(stderr, "Gecersiz port: %s\n", port_s);
		return 1;
	}

	fd = open_pinned("blocked_ports");
	if (fd < 0)
		return 1;

	memset(&key, 0, sizeof(key));   /* padding sifirlansin */
	key.port  = htons((__u16)port);
	key.proto = proto;

	if (ekle)
		err = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
	else
		err = bpf_map_delete_elem(fd, &key);

	if (err)
		fprintf(stderr, "Islem basarisiz: %s\n", strerror(errno));
	else
		printf("%s/%d %s\n", proto_s, port,
		       ekle ? "engellendi." : "engeli kaldirildi.");

	close(fd);
	return err ? 1 : 0;
}


/* ------------------------------------------------------------------ log */

static const char *proto_adi(__u8 p)
{
	switch (p) {
	case IPPROTO_TCP:  return "tcp";
	case IPPROTO_UDP:  return "udp";
	case IPPROTO_ICMP: return "icmp";
	default:           return "?";
	}
}

/* Ring buffer'dan gelen her olay icin cagrilir */
static int olay_isle(void *ctx, void *data, size_t len)
{
	const struct drop_event *e = data;
	char ip[INET_ADDRSTRLEN];
	double sn;

	(void)ctx;
	if (len < sizeof(*e))
		return 0;

	inet_ntop(AF_INET, &e->saddr, ip, sizeof(ip));
	sn = (double)e->ts / 1e9;   /* ns -> saniye (boot'tan beri) */

	if (e->dport)
		printf("[%12.3f] DROP %-15s -> %s/%-5u  (%s kurali)\n",
		       sn, ip, proto_adi(e->proto), ntohs(e->dport),
		       e->reason == REASON_IP ? "ip" : "port");
	else
		printf("[%12.3f] DROP %-15s     %-9s  (%s kurali)\n",
		       sn, ip, proto_adi(e->proto),
		       e->reason == REASON_IP ? "ip" : "port");

	fflush(stdout);
	return 0;
}

static int cmd_log(void)
{
	struct ring_buffer *rb;
	int fd;

	fd = open_pinned("events");
	if (fd < 0)
		return 1;

	rb = ring_buffer__new(fd, olay_isle, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Ring buffer acilamadi\n");
		close(fd);
		return 1;
	}

	printf("Drop olaylari dinleniyor (Ctrl+C ile cik)...\n\n");
	signal(SIGINT, on_signal);

	while (!stop) {
		int n = ring_buffer__poll(rb, 200 /* ms */);

		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "poll hatasi: %d\n", n);
			break;
		}
	}

	ring_buffer__free(rb);
	close(fd);
	return 0;
}

static int cmd_list(void)
{
	char buf[INET_ADDRSTRLEN];
	struct rule_stat val;
	int fd, bos = 1;

	fd = open_pinned("blocked_ips");
	if (fd < 0)
		return 1;

	printf("Engellenen IP'ler:\n");
	{
		struct lpm_key key, next_key, *pk = NULL;
		char gosterim[32];

		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
				inet_ntop(AF_INET, key.data, buf, sizeof(buf));
				snprintf(gosterim, sizeof(gosterim), "%s/%u",
					 buf, key.prefixlen);
				printf("  %-18s eslesme=%llu\n", gosterim,
				       (unsigned long long)val.hits);
				bos = 0;
			}
			pk = &key;
		}
	}
	if (bos)
		printf("  (yok)\n");
	close(fd);

	fd = open_pinned("blocked_ports");
	if (fd < 0)
		return 1;

	bos = 1;
	printf("\nEngellenen portlar:\n");
	{
		struct port_key key, next_key, *pk = NULL;

		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
				printf("  %-4s/%-5u eslesme=%llu\n",
				       key.proto == IPPROTO_TCP ? "tcp" : "udp",
				       ntohs(key.port),
				       (unsigned long long)val.hits);
				bos = 0;
			}
			pk = &key;
		}
	}
	if (bos)
		printf("  (yok)\n");
	close(fd);

	return 0;
}

/* ---------------------------------------------------------------- main */

static void usage(const char *prog)
{
	fprintf(stderr,
"Kullanim: %s <komut> [argumanlar]\n"
"\n"
"  load <arayuz>              XDP programini bagla\n"
"  unload <arayuz>            Programi kaldir\n"
"  stats [saniye]             Canli istatistik (varsayilan 1 sn)\n"
"  block-ip <ipv4[/prefix]>   Kaynak IP veya CIDR blogu engelle\n"
"  unblock-ip <ipv4[/prefix]> IP/CIDR engelini kaldir\n"
"  block-port <tcp|udp> <p>   Hedef portu engelle\n"
"  unblock-port <tcp|udp> <p> Port engelini kaldir\n"
"  log                        Canli drop olay akisi\n"
"  list                       Kurallari listele\n"
"\n"
"Ornek:\n"
"  sudo %s load veth0\n"
"  sudo %s block-port tcp 9999\n"
"  sudo %s stats\n"
"  sudo %s unload veth0\n", prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	libbpf_set_print(print_fn);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "load") && argc == 3)
		return cmd_load(argv[2]);
	if (!strcmp(argv[1], "unload") && argc == 3)
		return cmd_unload(argv[2]);
	if (!strcmp(argv[1], "stats"))
		return cmd_stats(argc > 2 ? atoi(argv[2]) : 1);
	if (!strcmp(argv[1], "block-ip") && argc == 3)
		return cmd_ip(argv[2], 1);
	if (!strcmp(argv[1], "unblock-ip") && argc == 3)
		return cmd_ip(argv[2], 0);
	if (!strcmp(argv[1], "block-port") && argc == 4)
		return cmd_port(argv[2], argv[3], 1);
	if (!strcmp(argv[1], "unblock-port") && argc == 4)
		return cmd_port(argv[2], argv[3], 0);
	if (!strcmp(argv[1], "log"))
		return cmd_log();
	if (!strcmp(argv[1], "list"))
		return cmd_list();

	usage(argv[0]);
	return 1;
}
