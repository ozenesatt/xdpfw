// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal HTTP sunucusu - salt okunur izleme paneli.
 * Kutuphane kullanmiyor, sadece POSIX socket API.
 *
 * Yalnizca 127.0.0.1'e baglanir; disaridan erisilemez.
 * Kural degistirme endpoint'i YOK - kimlik dogrulamasi olmayan bir
 * arayuze root yetkisiyle yazma izni vermek guvenlik acigi olurdu.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdpfw.h"
#include "panel.h"

#define PIN_DIR "/sys/fs/bpf/xdpfw"

extern volatile sig_atomic_t serve_stop;

static int pin_ac(const char *ad)
{
	char yol[256];

	snprintf(yol, sizeof(yol), PIN_DIR "/%s", ad);
	return bpf_obj_get(yol);
}

/* --- JSON uretimi --- */

static int json_stats(char *buf, size_t n)
{
	static const char *adlar[STAT_MAX] = {
		"total", "tcp", "udp", "icmp", "other",
		"passed", "dropped", "drop_ip", "drop_port", "drop_wl",
	};
	__u64 *percpu;
	int fd, ncpu, i, yaz = 0;
	__u32 k;

	fd = pin_ac("stats");
	if (fd < 0)
		return snprintf(buf, n, "\"stats\":null");

	ncpu = libbpf_num_possible_cpus();
	percpu = calloc(ncpu, sizeof(__u64));
	if (!percpu) {
		close(fd);
		return snprintf(buf, n, "\"stats\":null");
	}

	yaz += snprintf(buf + yaz, n - yaz, "\"stats\":{");
	for (k = 0; k < STAT_MAX; k++) {
		__u64 top = 0;

		if (bpf_map_lookup_elem(fd, &k, percpu) == 0)
			for (i = 0; i < ncpu; i++)
				top += percpu[i];
		yaz += snprintf(buf + yaz, n - yaz, "%s\"%s\":%llu",
				k ? "," : "", adlar[k], (unsigned long long)top);
	}
	yaz += snprintf(buf + yaz, n - yaz, "}");

	free(percpu);
	close(fd);
	return yaz;
}

static int json_kurallar(char *buf, size_t n)
{
	struct rule_stat val;
	char ip[INET_ADDRSTRLEN];
	int fd, yaz = 0, ilk = 1;

	yaz += snprintf(buf + yaz, n - yaz, "\"ips\":[");
	fd = pin_ac("blocked_ips");
	if (fd >= 0) {
		struct lpm_key key, next_key, *pk = NULL;

		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
				inet_ntop(AF_INET, key.data, ip, sizeof(ip));
				yaz += snprintf(buf + yaz, n - yaz,
						"%s{\"cidr\":\"%s/%u\",\"hits\":%llu}",
						ilk ? "" : ",", ip, key.prefixlen,
						(unsigned long long)val.hits);
				ilk = 0;
			}
			pk = &key;
		}
		close(fd);
	}
	yaz += snprintf(buf + yaz, n - yaz, "],\"ports\":[");

	ilk = 1;
	fd = pin_ac("blocked_ports");
	if (fd >= 0) {
		struct port_key key, next_key, *pk = NULL;

		while (bpf_map_get_next_key(fd, pk, &next_key) == 0) {
			key = next_key;
			if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
				yaz += snprintf(buf + yaz, n - yaz,
						"%s{\"proto\":\"%s\",\"port\":%u,\"hits\":%llu}",
						ilk ? "" : ",",
						key.proto == IPPROTO_TCP ? "tcp" : "udp",
						ntohs(key.port),
						(unsigned long long)val.hits);
				ilk = 0;
			}
			pk = &key;
		}
		close(fd);
	}
	yaz += snprintf(buf + yaz, n - yaz, "]");
	return yaz;
}

struct tk { __u32 ip; __u64 p; };

static int tk_cmp(const void *a, const void *b)
{
	const struct tk *x = a, *y = b;

	return (x->p < y->p) - (x->p > y->p);
}

static int json_talkers(char *buf, size_t n)
{
	struct tk liste[512];
	__u32 key, next_key, *pk = NULL;
	__u64 deger;
	char ip[INET_ADDRSTRLEN];
	int fd, adet = 0, i, yaz = 0;

	yaz += snprintf(buf + yaz, n - yaz, "\"talkers\":[");

	fd = pin_ac("talkers");
	if (fd < 0)
		return yaz + snprintf(buf + yaz, n - yaz, "]");

	while (bpf_map_get_next_key(fd, pk, &next_key) == 0 && adet < 512) {
		key = next_key;
		if (bpf_map_lookup_elem(fd, &key, &deger) == 0) {
			liste[adet].ip = key;
			liste[adet].p = deger;
			adet++;
		}
		pk = &key;
	}
	close(fd);

	qsort(liste, adet, sizeof(*liste), tk_cmp);

	for (i = 0; i < adet && i < 10; i++) {
		inet_ntop(AF_INET, &liste[i].ip, ip, sizeof(ip));
		yaz += snprintf(buf + yaz, n - yaz,
				"%s{\"ip\":\"%s\",\"packets\":%llu}",
				i ? "" : "", ip, (unsigned long long)liste[i].p);
		if (i + 1 < adet && i + 1 < 10)
			yaz += snprintf(buf + yaz, n - yaz, ",");
	}
	yaz += snprintf(buf + yaz, n - yaz, "]");
	return yaz;
}

static int json_mod(char *buf, size_t n)
{
	__u32 key = CFG_MODE, val = MODE_BLACKLIST;
	int fd = pin_ac("fw_config");

	if (fd >= 0) {
		bpf_map_lookup_elem(fd, &key, &val);
		close(fd);
	}
	return snprintf(buf, n, "\"mode\":\"%s\"",
			val == MODE_WHITELIST ? "whitelist" : "blacklist");
}

/* --- HTTP --- */

static void yanit_gonder(int c, const char *tip, const char *govde, size_t uzunluk)
{
	char baslik[256];
	int n;

	n = snprintf(baslik, sizeof(baslik),
		     "HTTP/1.1 200 OK\r\n"
		     "Content-Type: %s\r\n"
		     "Content-Length: %zu\r\n"
		     "Cache-Control: no-store\r\n"
		     "Connection: close\r\n\r\n", tip, uzunluk);
	write(c, baslik, n);
	write(c, govde, uzunluk);
}

int serve_calistir(int port)
{
	struct sockaddr_in adres = {0};
	int s, opt = 1;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	adres.sin_family = AF_INET;
	adres.sin_port = htons(port);
	adres.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* sadece 127.0.0.1 */

	if (bind(s, (struct sockaddr *)&adres, sizeof(adres)) < 0) {
		perror("bind");
		close(s);
		return 1;
	}
	if (listen(s, 8) < 0) {
		perror("listen");
		close(s);
		return 1;
	}

	printf("Panel hazir: http://localhost:%d\n", port);
	printf("Ctrl+C ile cik\n");

	while (!serve_stop) {
		char istek[1024], *json;
		int c, n, yaz = 0;

		c = accept(s, NULL, NULL);
		if (c < 0) {
			if (errno == EINTR)
				break;
			continue;
		}

		n = read(c, istek, sizeof(istek) - 1);
		if (n <= 0) {
			close(c);
			continue;
		}
		istek[n] = '\0';

		if (!strncmp(istek, "GET /api/stats", 14)) {
			json = malloc(65536);
			if (!json) {
				close(c);
				continue;
			}
			yaz += snprintf(json + yaz, 65536 - yaz, "{");
			yaz += json_mod(json + yaz, 65536 - yaz);
			yaz += snprintf(json + yaz, 65536 - yaz, ",");
			yaz += json_stats(json + yaz, 65536 - yaz);
			yaz += snprintf(json + yaz, 65536 - yaz, ",");
			yaz += json_kurallar(json + yaz, 65536 - yaz);
			yaz += snprintf(json + yaz, 65536 - yaz, ",");
			yaz += json_talkers(json + yaz, 65536 - yaz);
			yaz += snprintf(json + yaz, 65536 - yaz, "}");

			yanit_gonder(c, "application/json", json, yaz);
			free(json);
		} else {
			yanit_gonder(c, "text/html; charset=utf-8",
				     PANEL_HTML, strlen(PANEL_HTML));
		}
		close(c);
	}

	close(s);
	printf("\nPanel kapatildi.\n");
	return 0;
}
