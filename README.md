# xdpfw — XDP tabanlı ağ trafik izleyici ve firewall

Linux kernel'in XDP katmanında çalışan, paketleri ağ yığınına ulaşmadan
önce işleyen bir trafik izleme ve filtreleme aracı. Paketler `sk_buff`
yapısı oluşturulmadan, sürücü seviyesinde değerlendirilir.

## Özellikler

- Protokol bazlı paket sayımı (TCP / UDP / ICMP / diğer)
- CIDR blacklist (`10.0.0.0/8`) — LPM trie ile en uzun önek eşleşmesi
- Port blacklist (TCP / UDP)
- Canlı drop olay akışı — ring buffer üzerinden
- En çok paket gönderen kaynaklar (top talkers)
- Dosya tabanlı kural tanımı ve çalışma anında yeniden yükleme
- Kural bazlı eşleşme sayaçları ve drop sebebi ayrımı
- Whitelist modu (varsayılan DROP, yalnızca izinliler geçer)

## Gereksinimler

- Linux kernel 5.15+ (BTF açık: `CONFIG_DEBUG_INFO_BTF=y`)
- clang 12+, libbpf 1.0+, bpftool

Kali / Debian:

```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    bpftool gcc make iproute2 ethtool
```

Ubuntu'da `bpftool` ayrı paket değildir, `linux-tools-$(uname -r)` içinden gelir.

BTF kontrolü:

```bash
ls /sys/kernel/btf/vmlinux
```

## Derleme

```bash
make
```

Zincir: `vmlinux.h` üretilir → BPF programı bytecode'a derlenir →
skeleton üretilir → kullanıcı alanı programı linklenir.

## Kullanım

```bash
sudo ./xdpfw load veth0              # programı bağla, map'leri pinle
sudo ./xdpfw reload rules.conf       # kural dosyasını yükle

sudo ./xdpfw block-ip 10.0.0.0/8     # CIDR bloğu engelle
sudo ./xdpfw block-port tcp 8080     # port engelle
sudo ./xdpfw list                    # kuralları ve eşleşmeleri göster

sudo ./xdpfw mode                    # aktif modu göster
sudo ./xdpfw mode whitelist          # whitelist moduna geç
sudo ./xdpfw allow-ip 10.0.0.0/8     # whitelist modunda izin ver

sudo ./xdpfw stats                   # canlı sayaç tablosu
sudo ./xdpfw log                     # canlı drop olay akışı
sudo ./xdpfw top 10                  # en çok paket gönderen kaynaklar

sudo ./xdpfw unload veth0            # programı kaldır
sudo rm -rf /sys/fs/bpf/xdpfw        # map'leri de temizle
```

`load` komutu programı bağladıktan sonra çıkar; map'ler ve link bpffs'e
pinlendiği için XDP programı çalışmaya devam eder. Kurallar program
yeniden başlatılmadan eklenip kaldırılabilir.

## Demo

```bash
make
sudo ./scripts/demo.sh
```

İzole test ortamı kurar, kuralları yükler, üç farklı senaryoda trafik
üretir (engellenen IP / geçen IP / engellenen port), sonuçları gösterir
ve temizler.

## Kural dosyası
`reload` önce map'i temizler, sonra dosyayı yükler. Dosyadan silinen bir
kural map'te kalmaz — dosya, gerçek durumun tek kaynağıdır.

Kural kaynağı, kuralı uygulayan koddan bağımsızdır. Tehdit istihbaratı
beslemesi eklemek BPF programında değişiklik gerektirmez:

```bash
curl -s <feed-url> | grep -E '^[0-9]' | sed 's/^/block ip /' > feed.conf
sudo ./xdpfw reload feed.conf
```


## Çalışma modları

| Mod | `blocked_ips` anlamı | Eşleşme var | Eşleşme yok |
|---|---|---|---|
| `blacklist` (varsayılan) | yasak listesi | DROP | geçer |
| `whitelist` | izin listesi | geçer | DROP |

Aynı map iki modda farklı anlam taşır; ikisi aynı anda kullanılmadığı için
ayrı bir izin listesi tutulmaz. Port kuralları yalnızca blacklist modunda
işletilir.

ARP ve IPv4 dışı trafik whitelist modunda da geçer. Aksi hâlde adres
çözümlemesi çalışmaz ve izin verilmiş kaynaklar dahil hiçbir makine
haberleşemez — kural kendini kilitler.

Whitelist yaklaşımı bilinmeyen tehdide karşı da koruma sağlar (listede
olmayan her şey düşer), ancak tüm meşru trafiğin önceden tanımlanmasını
gerektirir. Endüstriyel kontrol sistemleri ve kritik ağlarda tercih edilir.

## Mimari

BPF programı her pakette Ethernet ve IPv4 başlıklarını ayrıştırır, kaynak
IP'yi CIDR blacklist'te arar, protokolü tespit edip hedef portu port
blacklist'te arar. Eşleşme varsa paket düşürülür ve ring buffer'a bir olay
yazılır.

```
NIC surucusu --> XDP programi --> XDP_PASS --> kernel ag yigini
                      |
                      +--> XDP_DROP
                      |
                      v
    stats / blocked_ips / blocked_ports / talkers / events
                      |
                      v
            bpffs (/sys/fs/bpf/xdpfw)
                      |
                      v
            kullanici alani CLI
```
### Map tipleri ve seçim gerekçeleri

| Map | Tip | Gerekçe |
|---|---|---|
| `stats` | PERCPU_ARRAY | Her CPU kendi kopyasını artırır, kilit gerekmez |
| `blocked_ips` | LPM_TRIE | En uzun önek eşleşmesi; `/8` için tek kayıt yeter |
| `blocked_ports` | HASH | Sabit anahtar kümesi, tam eşleşme yeterli |
| `talkers` | LRU_HASH | Anahtar kümesi sınırsız; taşmayı kernel yönetir |
| `events` | RINGBUF | Kernel→userspace olay akışı, sıralama korunur |

## Dosya yapısı

| Dosya | Açıklama |
|---|---|
| `src/xdpfw.bpf.c` | Kernel'de çalışan XDP programı |
| `src/xdpfw.c` | Yükleyici ve CLI |
| `src/xdpfw.h` | BPF ve kullanıcı alanının paylaştığı tipler |
| `src/vmlinux.h` | bpftool'un ürettiği kernel tipleri (git'te tutulmaz) |
| `src/xdpfw.skel.h` | bpftool'un ürettiği skeleton (git'te tutulmaz) |
| `rules.conf` | Kural dosyası |
| `scripts/testenv.sh` | veth + netns izole test ortamı |
| `scripts/demo.sh` | Uçtan uca demo |
| `scripts/bench.sh` | Yük testi ve pps ölçümü |
| `scripts/compare.sh` | iptables / nftables / XDP karşılaştırması |
| `docs/olcum.md` | Performans ölçüm sonuçları |
| `docs/gunluk.md` | Geliştirme günlüğü |

## Performans

Ayrıntılar ve ölçüm sınırları için `docs/olcum.md`.

Öne çıkan bulgu: aynı program içinde `XDP_DROP`, `XDP_PASS`'e göre
%57 daha yüksek paket işleme hızı verdi (454.610 vs 289.035 pps,
3 tekrar, sapma <%2). `XDP_PASS` durumunda paket kernel ağ yığınına
devam edip `sk_buff` ayrılması, protokol katmanı işlenmesi ve soket
araması maliyetlerini doğurur.

## Hata ayıklama

```bash
XDPFW_DEBUG=1 sudo ./xdpfw load veth0    # verifier logu
sudo bpftool net show                    # hangi arayüzde ne bağlı
sudo bpftool prog show                   # yüklü programlar
sudo bpftool map dump name stats         # map'in ham içeriği
```

## Bilinen sınırlar

- Yalnızca IPv4 desteklenir
- Bir arayüze aynı anda tek XDP programı bağlanabilir (`libxdp` dispatcher
  kullanılmıyor); ikinci yükleme `-EBUSY` verir
- IP fragmentasyonu dikkate alınmaz
- `talkers` map'i LRU olduğu için sayımlar yaklaşıktır; map dolduğunda
  eski kayıtlar düşer. İzleme için uygun, muhasebe için değil
- Yalnızca gelen (ingress) trafik işlenir; giden trafik için TC hook gerekir

## Yol haritası

- IPv6 desteği
- IP başına hız sınırlama (token bucket)
- SYN flood tespiti
- Web tabanlı izleme paneli
- `libxdp` ile çoklu program desteği
