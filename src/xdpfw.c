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
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "banner.h"
#include "xdpfw.h"
#include "xdpfw.skel.h"

#define PIN_DIR "/sys/fs/bpf/xdpfw"

static volatile sig_atomic_t stop;

/* serve.c ile paylasilan durdurma bayragi */
volatile sig_atomic_t serve_stop;
int serve_calistir(int port);

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
	serve_stop = 1;
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
	[STAT_DROP_RATE] = "  - hiz siniri",
	[STAT_DROP_DST] = "  - hedef IP",
	[STAT_DROP_RANGE] = "  - port araligi",
	[STAT_DROP_FLOW] = "  - bilesik kural",
	[STAT_DROP_WL] = "  - izinli degil",
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

static int cmd_load_sessiz(const char *ifname);
static int cmd_reload(const char *dosya);

static int cmd_load(const char *ifname)
{
	int r = cmd_load_sessiz(ifname);

	if (r == 0) {
		banner_bas();
		printf("XDP programi '%s' arayuzune baglandi.\n", ifname);
		printf("Kural ekle : sudo xdpfw engelle <ip>\n");
		printf("Istatistik : sudo xdpfw durum\n");
	}
	return r;
}

static int cmd_load_sessiz(const char *ifname)
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
	bpf_map__set_pin_path(skel->maps.blocked_flows, PIN_DIR "/blocked_flows");
	bpf_map__set_pin_path(skel->maps.blocked_dsts, PIN_DIR "/blocked_dsts");
	bpf_map__set_pin_path(skel->maps.port_ranges, PIN_DIR "/port_ranges");
	bpf_map__set_pin_path(skel->maps.rate_limits, PIN_DIR "/rate_limits");
	bpf_map__set_pin_path(skel->maps.buckets, PIN_DIR "/buckets");
	bpf_map__set_pin_path(skel->maps.events, PIN_DIR "/events");
	bpf_map__set_pin_path(skel->maps.talkers, PIN_DIR "/talkers");
	bpf_map__set_pin_path(skel->maps.fw_config, PIN_DIR "/fw_config");

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

static const char *sebep_adi(__u8 r)
{
	switch (r) {
	case REASON_IP:          return "ip";
	case REASON_PORT:        return "port";
	case REASON_NOT_ALLOWED: return "izinli degil";
	default:                 return "?";
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
		printf("[%12.3f] DROP %-15s -> %s/%-5u  (%s)\n",
		       sn, ip, proto_adi(e->proto), ntohs(e->dport),
		       sebep_adi(e->reason));
	else
		printf("[%12.3f] DROP %-15s     %-9s  (%s)\n",
		       sn, ip, proto_adi(e->proto),
		       sebep_adi(e->reason));

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





/* ----------------------------------------------------------------- flow */

/* "10.0.0.5 tcp 22" -> bilesik kural */
static int cmd_flow(const char *ipstr, const char *proto_s,
		    const char *port_s, int ekle)
{
	struct rule_stat val = {};
	struct flow_key key;
	struct in_addr addr;
	int fd, err, port;
	__u8 proto;

	if (inet_pton(AF_INET, ipstr, &addr) != 1) {
		fprintf(stderr, "Gecersiz IPv4 adresi: %s\n", ipstr);
		return 1;
	}
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

	fd = open_pinned("blocked_flows");
	if (fd < 0)
		return 1;

	memset(&key, 0, sizeof(key));   /* padding sifirlansin */
	key.saddr = addr.s_addr;
	key.dport = htons((__u16)port);
	key.proto = proto;

	if (ekle)
		err = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
	else
		err = bpf_map_delete_elem(fd, &key);

	if (err)
		fprintf(stderr, "Islem basarisiz: %s\n", strerror(errno));
	else
		printf("%s -> %s/%d %s\n", ipstr, proto_s, port,
		       ekle ? "engellendi." : "engeli kaldirildi.");

	close(fd);
	return err ? 1 : 0;
}


/* ------------------------------------------------------- hedef IP / aralik */

/* Hedef IP kurali (CIDR destekli) */
static int cmd_dst(const char *spec, int ekle)
{
	struct rule_stat val = {};
	struct lpm_key key;
	struct in_addr addr;
	char ipstr[64], *egik;
	int fd, err, prefixlen = 32;

	snprintf(ipstr, sizeof(ipstr), "%s", spec);
	egik = strchr(ipstr, '/');
	if (egik) {
		*egik = '\0';
		prefixlen = atoi(egik + 1);
		if (prefixlen < 0 || prefixlen > 32) {
			fprintf(stderr, "Gecersiz prefix: %s\n", spec);
			return 1;
		}
	}
	if (inet_pton(AF_INET, ipstr, &addr) != 1) {
		fprintf(stderr, "Gecersiz IPv4 adresi: %s\n", ipstr);
		return 1;
	}

	fd = open_pinned("blocked_dsts");
	if (fd < 0)
		return 1;

	memset(&key, 0, sizeof(key));
	key.prefixlen = (__u32)prefixlen;
	memcpy(key.data, &addr.s_addr, 4);

	err = ekle ? bpf_map_update_elem(fd, &key, &val, BPF_ANY)
		   : bpf_map_delete_elem(fd, &key);

	if (err)
		fprintf(stderr, "Islem basarisiz: %s\n", strerror(errno));
	else
		printf("hedef %s/%d %s\n", ipstr, prefixlen,
		       ekle ? "engellendi." : "engeli kaldirildi.");

	close(fd);
	return err ? 1 : 0;
}

/* Port araligi: dizide bos slot bul ve yaz */
static int cmd_range(const char *proto_s, const char *bas_s,
		     const char *son_s, int ekle)
{
	struct port_range pr, bos = {};
	int fd, bas, son, i, hedef = -1;
	__u8 proto;
	__u32 k;

	if (!strcmp(proto_s, "tcp"))
		proto = IPPROTO_TCP;
	else if (!strcmp(proto_s, "udp"))
		proto = IPPROTO_UDP;
	else {
		fprintf(stderr, "Protokol 'tcp' veya 'udp' olmali.\n");
		return 1;
	}

	bas = atoi(bas_s);
	son = atoi(son_s);
	if (bas < 1 || son > 65535 || bas > son) {
		fprintf(stderr, "Gecersiz aralik: %s-%s\n", bas_s, son_s);
		return 1;
	}

	fd = open_pinned("port_ranges");
	if (fd < 0)
		return 1;

	/* Once mevcut ayni kurali ara, yoksa bos slot bul */
	for (i = 0; i < MAX_RANGES; i++) {
		k = i;
		if (bpf_map_lookup_elem(fd, &k, &pr))
			continue;
		if (pr.proto == proto && pr.bas == bas && pr.son == son) {
			hedef = i;
			break;
		}
		if (pr.proto == 0 && hedef < 0)
			hedef = i;
	}

	if (hedef < 0) {
		fprintf(stderr, "Aralik tablosu dolu (max %d).\n", MAX_RANGES);
		close(fd);
		return 1;
	}

	k = hedef;
	if (ekle) {
		memset(&pr, 0, sizeof(pr));
		pr.bas = (__u16)bas;
		pr.son = (__u16)son;
		pr.proto = proto;
		bpf_map_update_elem(fd, &k, &pr, BPF_ANY);
		printf("%s/%d-%d engellendi.\n", proto_s, bas, son);
	} else {
		bpf_map_update_elem(fd, &k, &bos, BPF_ANY);
		printf("%s/%d-%d engeli kaldirildi.\n", proto_s, bas, son);
	}

	close(fd);
	return 0;
}



/* ------------------------------------------------------------ hiz siniri */

/* "10.0.0.0/8 1000 [burst]" -> hiz siniri kurali */
static int cmd_rate(const char *spec, const char *hiz_s,
		    const char *burst_s, int ekle)
{
	struct limit_val val = {};
	struct lpm_key key;
	struct in_addr addr;
	char ipstr[64], *egik;
	int fd, err, prefixlen = 32, hiz, burst;

	snprintf(ipstr, sizeof(ipstr), "%s", spec);
	egik = strchr(ipstr, '/');
	if (egik) {
		*egik = '\0';
		prefixlen = atoi(egik + 1);
		if (prefixlen < 0 || prefixlen > 32) {
			fprintf(stderr, "Gecersiz prefix: %s\n", spec);
			return 1;
		}
	}
	if (inet_pton(AF_INET, ipstr, &addr) != 1) {
		fprintf(stderr, "Gecersiz IPv4 adresi: %s\n", ipstr);
		return 1;
	}

	if (ekle) {
		hiz = atoi(hiz_s);
		if (hiz < 1) {
			fprintf(stderr, "Hiz en az 1 olmali (paket/saniye).\n");
			return 1;
		}
		/* Burst verilmezse hizin 2 kati - kisa patlamalara izin */
		burst = burst_s ? atoi(burst_s) : hiz * 2;
		if (burst < hiz)
			burst = hiz;
		val.hiz = (__u32)hiz;
		val.kapasite = (__u32)burst;
	}

	fd = open_pinned("rate_limits");
	if (fd < 0)
		return 1;

	memset(&key, 0, sizeof(key));
	key.prefixlen = (__u32)prefixlen;
	memcpy(key.data, &addr.s_addr, 4);

	err = ekle ? bpf_map_update_elem(fd, &key, &val, BPF_ANY)
		   : bpf_map_delete_elem(fd, &key);

	if (err)
		fprintf(stderr, "Islem basarisiz: %s\n", strerror(errno));
	else if (ekle)
		printf("%s/%d icin hiz siniri: %d paket/sn (burst %d)\n",
		       ipstr, prefixlen, val.hiz, val.kapasite);
	else
		printf("%s/%d hiz siniri kaldirildi.\n", ipstr, prefixlen);

	close(fd);
	return err ? 1 : 0;
}

/* --------------------------------------------------------------- daemon */

#define LOG_DIZIN "/var/log/xdpfw"
#define LOG_DOSYA LOG_DIZIN "/events.jsonl"
#define LOG_MAX   (10 * 1024 * 1024)   /* 10 MB -> dondur */

static FILE *log_fp;

static const char *proto_adi_us(__u8 p)
{
	switch (p) {
	case IPPROTO_TCP:  return "tcp";
	case IPPROTO_UDP:  return "udp";
	case IPPROTO_ICMP: return "icmp";
	default:           return "other";
	}
}

static const char *sebep_adi_us(__u8 r)
{
	switch (r) {
	case REASON_IP:          return "ip";
	case REASON_DST:         return "dst";
	case REASON_RANGE:       return "range";
	case REASON_FLOW:        return "flow";
	case REASON_PORT:        return "port";
	case REASON_NOT_ALLOWED: return "not_allowed";
	default:                 return "unknown";
	}
}

/* Dosya buyuduyse .1 uzantisiyla dondur */
static void log_dondur(void)
{
	char eski[256];
	long boyut;

	if (!log_fp)
		return;
	boyut = ftell(log_fp);
	if (boyut < LOG_MAX)
		return;

	fclose(log_fp);
	snprintf(eski, sizeof(eski), LOG_DOSYA ".1");
	rename(LOG_DOSYA, eski);
	log_fp = fopen(LOG_DOSYA, "a");
}

/*
 * JSON Lines formati: her satir bagimsiz bir JSON nesnesi.
 * jq ile islenebilir, SIEM'e beslenebilir, satir satir okunabilir.
 */
static int log_yaz(void *ctx, void *data, size_t len)
{
	const struct drop_event *e = data;
	char ip[INET_ADDRSTRLEN];
	time_t simdi;

	(void)ctx;
	if (len < sizeof(*e) || !log_fp)
		return 0;

	inet_ntop(AF_INET, &e->saddr, ip, sizeof(ip));
	simdi = time(NULL);

	fprintf(log_fp,
		"{\"time\":%ld,\"uptime_ns\":%llu,\"src\":\"%s\","
		"\"dport\":%u,\"proto\":\"%s\",\"reason\":\"%s\"}\n",
		(long)simdi, (unsigned long long)e->ts, ip,
		ntohs(e->dport), proto_adi_us(e->proto), sebep_adi_us(e->reason));

	fflush(log_fp);
	log_dondur();
	return 0;
}

static int cmd_daemon(const char *ifname, const char *kural_dosyasi)
{
	struct ring_buffer *rb;
	int rb_fd, err;

	/* Once XDP'yi bagla (banner basmadan) */
	err = cmd_load_sessiz(ifname);
	if (err)
		return err;

	if (kural_dosyasi && cmd_reload(kural_dosyasi))
		fprintf(stderr, "Uyari: kural dosyasi yuklenemedi\n");

	mkdir(LOG_DIZIN, 0750);
	log_fp = fopen(LOG_DOSYA, "a");
	if (!log_fp)
		fprintf(stderr, "Uyari: %s acilamadi (%s), log yazilmayacak\n",
			LOG_DOSYA, strerror(errno));

	rb_fd = open_pinned("events");
	if (rb_fd < 0)
		return 1;

	rb = ring_buffer__new(rb_fd, log_yaz, NULL, NULL);
	if (!rb) {
		close(rb_fd);
		return 1;
	}

	printf("xdpfw servisi calisiyor (arayuz: %s)\n", ifname);
	printf("Log: %s\n", LOG_DOSYA);
	fflush(stdout);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	while (!stop) {
		int n = ring_buffer__poll(rb, 500);

		if (n < 0 && n != -EINTR)
			break;
	}

	printf("Kapaniyor...\n");
	ring_buffer__free(rb);
	close(rb_fd);
	if (log_fp)
		fclose(log_fp);

	/* XDP bagli kalir - unload ile ayrilir */
	return 0;
}

/* ----------------------------------------------------------------- mode */

static __u32 mod_oku_us(void)
{
	__u32 key = CFG_MODE, val = MODE_BLACKLIST;
	int fd = open_pinned("fw_config");

	if (fd < 0)
		return MODE_BLACKLIST;
	bpf_map_lookup_elem(fd, &key, &val);
	close(fd);
	return val;
}

static int cmd_mode(const char *yeni)
{
	__u32 key = CFG_MODE, val;
	int fd;

	fd = open_pinned("fw_config");
	if (fd < 0)
		return 1;

	if (!yeni) {
		/* sadece goster */
		val = MODE_BLACKLIST;
		bpf_map_lookup_elem(fd, &key, &val);
		printf("Aktif mod: %s\n",
		       val == MODE_WHITELIST ? "whitelist" : "blacklist");
		close(fd);
		return 0;
	}

	if (!strcmp(yeni, "blacklist"))
		val = MODE_BLACKLIST;
	else if (!strcmp(yeni, "whitelist"))
		val = MODE_WHITELIST;
	else {
		fprintf(stderr, "Mod 'blacklist' veya 'whitelist' olmali.\n");
		close(fd);
		return 1;
	}

	if (bpf_map_update_elem(fd, &key, &val, BPF_ANY)) {
		fprintf(stderr, "Mod degistirilemedi: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	printf("Mod: %s\n", yeni);
	if (val == MODE_WHITELIST) {
		printf("\nDIKKAT: Whitelist modunda izinli listede OLMAYAN tum\n");
		printf("IPv4 trafigi dusurulur. ARP her zaman gecer (yoksa ag\n");
		printf("tamamen kilitlenirdi). Port kurallari bu modda devre disidir.\n");
		printf("Izin vermek icin: sudo ./xdpfw allow-ip <ipv4[/prefix]>\n");
	}

	close(fd);
	return 0;
}

/* --------------------------------------------------------------- reload */

/* Bir map'teki tum kayitlari sil */
static int map_temizle(int fd, size_t key_size)
{
	unsigned char key[64], next_key[64];
	void *pk = NULL;
	int silinen = 0;

	if (key_size > sizeof(key))
		return -1;

	/*
	 * Silme sirasinda get_next_key kullanmak zor: sildigin anahtarin
	 * yerini kaybediyorsun. Bu yuzden her turda bastan basliyoruz.
	 */
	while (bpf_map_get_next_key(fd, pk, next_key) == 0) {
		memcpy(key, next_key, key_size);
		if (bpf_map_delete_elem(fd, key) == 0)
			silinen++;
		pk = NULL;   /* bastan tara */
	}
	return silinen;
}

static int cmd_reload(const char *dosya)
{
	FILE *f;
	char satir[256];
	int ip_fd, port_fd;
	int satir_no = 0, eklenen = 0, hatali = 0;

	f = fopen(dosya, "r");
	if (!f) {
		fprintf(stderr, "Dosya acilamadi: %s (%s)\n", dosya, strerror(errno));
		return 1;
	}

	ip_fd = open_pinned("blocked_ips");
	if (ip_fd < 0) {
		fclose(f);
		return 1;
	}
	port_fd = open_pinned("blocked_ports");
	if (port_fd < 0) {
		close(ip_fd);
		fclose(f);
		return 1;
	}

	/*
	 * Once temizle, sonra doldur.
	 * Boylece dosyadan silinen kural map'te kalmaz - dosya neyi
	 * soyluyorsa map o hale gelir (declarative).
	 */
	printf("Mevcut kurallar temizleniyor: %d IP, %d port\n",
	       map_temizle(ip_fd, sizeof(struct lpm_key)),
	       map_temizle(port_fd, sizeof(struct port_key)));

	close(ip_fd);
	close(port_fd);

	while (fgets(satir, sizeof(satir), f)) {
		char komut[32] = "", tip[32] = "", a1[64] = "", a2[64] = "";
		int n;

		satir_no++;

		/* yorum ve bos satirlari atla */
		{
			char *p = satir;

			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '#' || *p == '\n' || *p == '\0')
				continue;
		}

		n = sscanf(satir, "%31s %31s %63s %63s", komut, tip, a1, a2);

		if (n < 3 || strcmp(komut, "block")) {
			fprintf(stderr, "  satir %d: anlasilmadi -> %s", satir_no, satir);
			hatali++;
			continue;
		}

		if (!strcmp(tip, "ip") && n == 3) {
			if (cmd_ip(a1, 1) == 0)
				eklenen++;
			else
				hatali++;
		} else if (!strcmp(tip, "port") && n == 4) {
			if (cmd_port(a1, a2, 1) == 0)
				eklenen++;
			else
				hatali++;
		} else {
			fprintf(stderr, "  satir %d: gecersiz kural -> %s", satir_no, satir);
			hatali++;
		}
	}

	fclose(f);
	printf("\n%d kural yuklendi", eklenen);
	if (hatali)
		printf(", %d satir atlandi", hatali);
	printf(".\n");
	return hatali ? 1 : 0;
}

/* ------------------------------------------------------------------ top */

struct talker {
	__u32 ip;
	__u64 paket;
};

/* qsort icin: cok paketten aza sirala */
static int talker_cmp(const void *a, const void *b)
{
	const struct talker *x = a, *y = b;

	if (x->paket < y->paket)
		return 1;
	if (x->paket > y->paket)
		return -1;
	return 0;
}

static int cmd_top(int adet)
{
	struct talker *liste = NULL;
	__u32 key, next_key, *pk = NULL;
	char buf[INET_ADDRSTRLEN];
	__u64 deger, toplam = 0;
	int fd, n = 0, kapasite = 256, i;

	fd = open_pinned("talkers");
	if (fd < 0)
		return 1;

	liste = malloc(kapasite * sizeof(*liste));
	if (!liste) {
		close(fd);
		return 1;
	}

	/* Tum map'i tara */
	while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
		key = next_key;
		if (bpf_map_lookup_elem(fd, &key, &deger) == 0) {
			if (n == kapasite) {
				struct talker *yeni;

				kapasite *= 2;
				yeni = realloc(liste, kapasite * sizeof(*liste));
				if (!yeni)
					break;
				liste = yeni;
			}
			liste[n].ip = key;
			liste[n].paket = deger;
			toplam += deger;
			n++;
		}
		pk = &key;
	}

	qsort(liste, n, sizeof(*liste), talker_cmp);

	printf("En cok paket gonderen kaynaklar (toplam %d adres, %llu paket)\n\n",
	       n, (unsigned long long)toplam);
	printf("%-4s %-16s %14s %8s\n", "#", "KAYNAK IP", "PAKET", "ORAN");
	printf("--------------------------------------------------\n");

	for (i = 0; i < n && i < adet; i++) {
		double oran = toplam ? 100.0 * liste[i].paket / toplam : 0.0;

		inet_ntop(AF_INET, &liste[i].ip, buf, sizeof(buf));
		printf("%-4d %-16s %14llu %7.1f%%\n", i + 1, buf,
		       (unsigned long long)liste[i].paket, oran);
	}
	if (n == 0)
		printf("(kayit yok)\n");

	free(liste);
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

	{
		__u32 m = mod_oku_us();

		printf("Mod: %s\n\n", m == MODE_WHITELIST ? "whitelist" : "blacklist");
		printf("%s:\n", m == MODE_WHITELIST ? "Izinli IP'ler" : "Engellenen IP'ler");
	}
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
	printf("\nHiz sinirlari:\n");
	fd = open_pinned("rate_limits");
	if (fd >= 0) {
		struct lpm_key key, next_key, *pk = NULL;
		struct limit_val lv;
		char g[32];
		int kfd;

		kfd = open_pinned("buckets");
		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &lv) == 0) {
				struct token_kova kv = {};
				__u32 ip4;

				inet_ntop(AF_INET, key.data, buf, sizeof(buf));
				snprintf(g, sizeof(g), "%s/%u", buf, key.prefixlen);
				memcpy(&ip4, key.data, 4);
				if (kfd >= 0)
					bpf_map_lookup_elem(kfd, &ip4, &kv);
				printf("  %-18s %u pkt/sn (burst %u)  gecen=%llu dusen=%llu\n",
				       g, lv.hiz, lv.kapasite,
				       (unsigned long long)kv.gecen,
				       (unsigned long long)kv.dusen);
				bos = 0;
			}
			pk = &key;
		}
		if (kfd >= 0)
			close(kfd);
		close(fd);
	}
	if (bos)
		printf("  (yok)\n");

	bos = 1;
	printf("\nEngellenen hedef IP'ler:\n");
	fd = open_pinned("blocked_dsts");
	if (fd >= 0) {
		struct lpm_key key, next_key, *pk = NULL;
		char g[32];

		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
				inet_ntop(AF_INET, key.data, buf, sizeof(buf));
				snprintf(g, sizeof(g), "%s/%u", buf, key.prefixlen);
				printf("  %-18s eslesme=%llu\n", g,
				       (unsigned long long)val.hits);
				bos = 0;
			}
			pk = &key;
		}
		close(fd);
	}
	if (bos)
		printf("  (yok)\n");

	bos = 1;
	printf("\nPort araliklari:\n");
	fd = open_pinned("port_ranges");
	if (fd >= 0) {
		struct port_range pr;
		__u32 k;
		int i;

		for (i = 0; i < MAX_RANGES; i++) {
			k = i;
			if (bpf_map_lookup_elem(fd, &k, &pr) || pr.proto == 0)
				continue;
			printf("  %-4s/%u-%-5u eslesme=%llu\n",
			       pr.proto == IPPROTO_TCP ? "tcp" : "udp",
			       pr.bas, pr.son, (unsigned long long)pr.hits);
			bos = 0;
		}
		close(fd);
	}
	if (bos)
		printf("  (yok)\n");

	bos = 1;
	printf("\nEngellenen akislar (IP -> port):\n");
	fd = open_pinned("blocked_flows");
	if (fd >= 0) {
		struct flow_key key, next_key, *pk = NULL;

		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
				inet_ntop(AF_INET, &key.saddr, buf, sizeof(buf));
				printf("  %-15s -> %s/%-5u eslesme=%llu\n", buf,
				       key.proto == IPPROTO_TCP ? "tcp" : "udp",
				       ntohs(key.dport),
				       (unsigned long long)val.hits);
				bos = 0;
			}
			pk = &key;
		}
		close(fd);
	}
	if (bos)
		printf("  (yok)\n");

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
	banner_bas();
	fprintf(stderr,
"Kullanim: %s <komut> [argumanlar]\n"
"\n"
"  load / basla <arayuz>      XDP programini bagla\n"
"  unload / durdur <arayuz>   Programi kaldir\n"
"  stats / durum [saniye]     Canli istatistik (varsayilan 1 sn)\n"
"  mode / mod [black|white]   Modu goster veya degistir\n"
"  block-ip / engelle <ip>    Kaynak IP veya CIDR blogu engelle\n"
"  allow-ip / izin <ip>       Whitelist modunda izin ver\n"
"  unblock-ip / kaldir <ip>   IP/CIDR engelini kaldir\n"
"  rate-limit / hiz-sinir <ip[/prefix]> <pkt/sn> [burst]\n"
"  unrate-limit / sinir-kaldir <ip[/prefix]>\n"
"  block-dst / engelle-hedef  <ip[/prefix]>  Hedef IP engelle\n"
"  unblock-dst / kaldir-hedef <ip[/prefix]>\n"
"  block-range / engelle-aralik <tcp|udp> <bas> <son>\n"
"  unblock-range / kaldir-aralik <tcp|udp> <bas> <son>\n"
"  block-flow / engelle-akis  <ip> <tcp|udp> <port>\n"
"  unblock-flow / kaldir-akis <ip> <tcp|udp> <port>\n"
"  block-port / engelle-port  <tcp|udp> <port>\n"
"  unblock-port / kaldir-port <tcp|udp> <port>\n"
"  log / kayit                Canli drop olay akisi\n"
"  top / zirve [n]            En cok paket gonderen IP'ler\n"
"  list / kurallar            Kurallari listele\n"
"  reload / yenile <dosya>    Kural dosyasindan yeniden yukle\n"
"  serve / panel [port]       Web paneli (varsayilan 8080, sadece localhost)\n"
"  daemon <arayuz> [kural]    Servis modu: bagla, dinle, log yaz\n"
"\n"
"Ornek:\n"
"  sudo %s basla veth0\n"
"  sudo %s engelle 10.0.0.0/8\n"
"  sudo %s durum\n"
"  sudo %s panel\n", prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
	libbpf_set_print(print_fn);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if ((!strcmp(argv[1], "load") || !strcmp(argv[1], "basla")) && argc == 3)
		return cmd_load(argv[2]);
	if ((!strcmp(argv[1], "unload") || !strcmp(argv[1], "durdur")) && argc == 3)
		return cmd_unload(argv[2]);
	if (!strcmp(argv[1], "stats") || !strcmp(argv[1], "durum"))
		return cmd_stats(argc > 2 ? atoi(argv[2]) : 1);
	if (!strcmp(argv[1], "mode") || !strcmp(argv[1], "mod"))
		return cmd_mode(argc > 2 ? argv[2] : NULL);
	if ((!strcmp(argv[1], "allow-ip") || !strcmp(argv[1], "izin")) && argc == 3)
		return cmd_ip(argv[2], 1);
	if ((!strcmp(argv[1], "block-ip") || !strcmp(argv[1], "engelle")) && argc == 3)
		return cmd_ip(argv[2], 1);
	if ((!strcmp(argv[1], "unblock-ip") || !strcmp(argv[1], "kaldir")) && argc == 3)
		return cmd_ip(argv[2], 0);
	if ((!strcmp(argv[1], "rate-limit") || !strcmp(argv[1], "hiz-sinir")) && argc >= 4)
		return cmd_rate(argv[2], argv[3], argc > 4 ? argv[4] : NULL, 1);
	if ((!strcmp(argv[1], "unrate-limit") || !strcmp(argv[1], "sinir-kaldir")) && argc == 3)
		return cmd_rate(argv[2], NULL, NULL, 0);
	if ((!strcmp(argv[1], "block-dst") || !strcmp(argv[1], "engelle-hedef")) && argc == 3)
		return cmd_dst(argv[2], 1);
	if ((!strcmp(argv[1], "unblock-dst") || !strcmp(argv[1], "kaldir-hedef")) && argc == 3)
		return cmd_dst(argv[2], 0);
	if ((!strcmp(argv[1], "block-range") || !strcmp(argv[1], "engelle-aralik")) && argc == 5)
		return cmd_range(argv[2], argv[3], argv[4], 1);
	if ((!strcmp(argv[1], "unblock-range") || !strcmp(argv[1], "kaldir-aralik")) && argc == 5)
		return cmd_range(argv[2], argv[3], argv[4], 0);
	if ((!strcmp(argv[1], "block-flow") || !strcmp(argv[1], "engelle-akis")) && argc == 5)
		return cmd_flow(argv[2], argv[3], argv[4], 1);
	if ((!strcmp(argv[1], "unblock-flow") || !strcmp(argv[1], "kaldir-akis")) && argc == 5)
		return cmd_flow(argv[2], argv[3], argv[4], 0);
	if ((!strcmp(argv[1], "block-port") || !strcmp(argv[1], "engelle-port")) && argc == 4)
		return cmd_port(argv[2], argv[3], 1);
	if ((!strcmp(argv[1], "unblock-port") || !strcmp(argv[1], "kaldir-port")) && argc == 4)
		return cmd_port(argv[2], argv[3], 0);
	if (!strcmp(argv[1], "top") || !strcmp(argv[1], "zirve"))
		return cmd_top(argc > 2 ? atoi(argv[2]) : 10);
	if (!strcmp(argv[1], "log") || !strcmp(argv[1], "kayit"))
		return cmd_log();
	if (!strcmp(argv[1], "serve") || !strcmp(argv[1], "panel")) {
		signal(SIGINT, on_signal);
		signal(SIGTERM, on_signal);
		return serve_calistir(argc > 2 ? atoi(argv[2]) : 8080);
	}
	if (!strcmp(argv[1], "daemon") && argc >= 3)
		return cmd_daemon(argv[2], argc > 3 ? argv[3] : NULL);
	if ((!strcmp(argv[1], "reload") || !strcmp(argv[1], "yenile")) && argc == 3)
		return cmd_reload(argv[2]);
	if (!strcmp(argv[1], "list") || !strcmp(argv[1], "kurallar"))
		return cmd_list();

	usage(argv[0]);
	return 1;
}
