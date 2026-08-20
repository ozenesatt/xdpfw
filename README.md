# xdpfw — XDP tabanlı ağ trafik izleyici ve firewall

Linux kernel'in XDP katmanında çalışan, paketleri ağ yığınına ulaşmadan
önce işleyen bir trafik izleme ve filtreleme aracı. Paketler `sk_buff`
yapısı oluşturulmadan, sürücü seviyesinde değerlendirilir.

## Özellikler

**Filtreleme**
- Kaynak IP / CIDR blacklist (LPM trie, en uzun önek eşleşmesi)
- Hedef IP / CIDR blacklist
- Hedef port (TCP / UDP)
- Port aralığı (`8000-9000`)
- Bileşik kural (kaynak IP + protokol + hedef port)
- IP başına hız sınırlama (token bucket)
- Whitelist modu (varsayılan DROP)

**İzleme**
- Protokol bazlı paket sayımı ve drop sebebi ayrımı
- Canlı drop olay akışı (ring buffer)
- En çok paket gönderen kaynaklar (top talkers)
- Web paneli: sayaç kartları, 60 saniyelik pps grafiği, protokol
  dağılımı, kural tablosu, canlı olay akışı

**Operasyon**
- systemd servisi, boot'ta otomatik başlatma
- JSON Lines log (`/var/log/xdpfw/events.jsonl`), logrotate
- Dosya tabanlı kural tanımı ve çalışma anında yeniden yükleme
- Türkçe ve İngilizce komut adları

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
sudo make install                     # /usr/sbin/xdpfw + systemd birimi

sudo xdpfw basla veth0                # programı bağla, map'leri pinle
sudo xdpfw yenile /etc/xdpfw/rules.conf
```

**Kural komutları**

```bash
sudo xdpfw engelle 10.0.0.0/8              # kaynak IP / CIDR
sudo xdpfw engelle-hedef 192.168.1.10      # hedef IP
sudo xdpfw engelle-port tcp 22             # hedef port
sudo xdpfw engelle-aralik tcp 8000 9000    # port aralığı
sudo xdpfw engelle-akis 10.0.0.5 tcp 22    # bileşik kural
sudo xdpfw hiz-sinir 10.0.0.0/8 1000 2000  # 1000 pkt/sn, burst 2000
sudo xdpfw mod whitelist                   # mod değiştir
sudo xdpfw izin 10.0.0.5                   # whitelist modunda izin ver
```

Her komutun `kaldir-` öneki ile karşılığı vardır (`kaldir`, `kaldir-hedef`,
`kaldir-port`, `kaldir-aralik`, `kaldir-akis`, `sinir-kaldir`).

**İzleme komutları**

```bash
sudo xdpfw durum                      # canlı sayaç tablosu
sudo xdpfw kurallar                   # kurallar ve eşleşme sayıları
sudo xdpfw kayit                      # canlı drop olay akışı
sudo xdpfw zirve 10                   # en çok paket gönderenler
sudo xdpfw panel                      # web paneli (localhost:8080)
```

**Servis olarak**

```bash
sudo systemctl enable --now xdpfw
sudo systemctl status xdpfw
sudo journalctl -u xdpfw -f
sudo tail -f /var/log/xdpfw/events.jsonl | jq
```

Arayüz adı `/etc/xdpfw/xdpfw.env` içinden ayarlanır.

**Kaldırma**

```bash
sudo xdpfw durdur veth0
sudo rm -rf /sys/fs/bpf/xdpfw
```

Tüm komutların İngilizce karşılığı da çalışır (`load`, `unload`, `stats`,
`list`, `log`, `top`, `serve`, `reload`, `block-ip`, `block-port`, ...).

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
| `blocked_ips` | LPM_TRIE | En uzun önek eşleşmesi; `/8` için tek kayıt |
| `blocked_dsts` | LPM_TRIE | Hedef IP, aynı gerekçe |
| `blocked_ports` | HASH | Sabit anahtar kümesi, tam eşleşme yeterli |
| `blocked_flows` | HASH | `{IP, proto, port}` üçlüsü, tam eşleşme |
| `port_ranges` | ARRAY | Aralık hash'lenemez; 16 slot üzerinde döngü |
| `rate_limits` | LPM_TRIE | CIDR bazlı limit tanımı |
| `buckets` | LRU_HASH | IP başına kova; anahtar kümesi sınırsız |
| `talkers` | LRU_HASH | Sınırsız anahtar, taşmayı kernel yönetir |
| `events` | RINGBUF | Kernel→userspace olay akışı, sıralama korunur |
| `fw_config` | ARRAY | Çalışma anında değişebilen ayar (mod) |

### Kural değerlendirme sırası

Spesifikten genele:

1. Kaynak IP / CIDR
2. Hız sınırı (token bucket)
3. Hedef IP / CIDR
4. Bileşik kural (IP + proto + port)
5. Port aralığı
6. Hedef port

Bir kural eşleşince paket düşer, sonraki kontroller çalışmaz.

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

| Yapılandırma | pps |
|---|---|
| Kural yok | 272.888 |
| 8 kural yüklü, hiçbiri eşleşmiyor | 286.933 |
| İlk kuralda DROP | 414.985 |

İki bulgu:

**Kural sayısı işlem hızını etkilemiyor.** Sekiz kural yüklüyken ve her
paket tüm kontrollerden geçerken ölçülen değer, kuralsız duruma göre
ölçüm gürültüsü kadar fark gösterdi. BPF map aramaları düşük maliyetli.

**Paketi düşürmek geçirmekten %52 hızlı.** `XDP_PASS` durumunda paket
kernel ağ yığınına devam eder: `sk_buff` ayrılır, protokol katmanları
işlenir, soket aranır. `XDP_DROP`'ta bu maliyetler ödenmez.

Ölçümler sanal arayüz (veth) üzerinde, VirtualBox içinde yapılmıştır;
mutlak değerler değil aynı ortamdaki göreli karşılaştırma anlamlıdır.

## Hata ayıklama

```bash
XDPFW_DEBUG=1 sudo ./xdpfw load veth0    # verifier logu
sudo bpftool net show                    # hangi arayüzde ne bağlı
sudo bpftool prog show                   # yüklü programlar
sudo bpftool map dump name stats         # map'in ham içeriği
```

## Bilinen sınırlar

- Yalnızca IPv4 desteklenir
- Yalnızca gelen (ingress) trafik işlenir; giden trafik için TC hook gerekir
- Bağlantı durumu takibi yoktur (stateless); iptables'ın
  `ESTABLISHED,RELATED` karşılığı bulunmaz
- Bileşik kuralda kaynak IP tam adres olmalıdır (`/32`); hash map önek
  eşleşmesi yapamaz, LPM trie de port bilgisi taşıyamaz
- Port aralığı en fazla 16 tanedir (`MAX_RANGES`), dizi üzerinde döngü
  derleme zamanında açıldığı için sabit
- Hız sınırlamada kova güncellemesi tam atomik değildir; yarış durumunda
  birkaç paket sınırın üzerinde geçebilir
- `talkers` ve `buckets` map'leri LRU'dur; sayımlar yaklaşıktır, map
  dolduğunda eski kayıtlar düşer. İzleme için uygun, muhasebe için değil
- Bir arayüze aynı anda tek XDP programı bağlanabilir (`libxdp` dispatcher
  kullanılmıyor); ikinci yükleme `-EBUSY` verir
- IP fragmentasyonu dikkate alınmaz
- Web paneli salt okunurdur ve yalnızca `127.0.0.1`'e bağlanır

## Yol haritası

- IPv6 desteği
- TC hook ile giden (egress) trafik kontrolü
- Bağlantı durumu takibi
- SYN flood tespiti (TCP bayrak analizi)
- Kural TTL'i (süreli engelleme)
- Geolocation tabanlı filtreleme
- Tehdit istihbaratı beslemesi entegrasyonu
- `libxdp` ile çoklu program desteği
