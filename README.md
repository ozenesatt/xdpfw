# xdpfw — XDP tabanlı ağ trafik izleyici ve firewall

Linux kernel'in XDP katmanında çalışan, paketleri ağ yığınına ulaşmadan önce
işleyen bir trafik izleme aracı. Paketler `sk_buff` yapısı oluşturulmadan,
sürücü seviyesinde değerlendirilir.

## Durum

- [x] Protokol bazlı paket sayımı (TCP / UDP / ICMP / diğer)
- [x] Canlı istatistik gösterimi (toplam + paket/saniye)
- [ ] IP blacklist
- [ ] Port blacklist
- [ ] CIDR desteği
- [ ] Canlı drop log akışı

## Gereksinimler

- Linux kernel 5.15+ (BTF açık: `CONFIG_DEBUG_INFO_BTF=y`)
- clang 12+, libbpf 1.0+, bpftool

Kali / Debian:

```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    bpftool gcc make iproute2 ethtool
```

Ubuntu'da `bpftool` ayrı paket değil, `linux-tools-$(uname -r)` içinden gelir.

BTF kontrolü:

```bash
ls /sys/kernel/btf/vmlinux
```

## Derleme

```bash
make
```

Sırasıyla: `vmlinux.h` üretilir → BPF programı bytecode'a derlenir →
skeleton üretilir → kullanıcı alanı programı linklenir.

## Kullanım

```bash
sudo ./xdpfw <arayüz>
```

Canlı sayaç tablosu gösterir, `Ctrl+C` ile çıkar ve XDP programını
otomatik kaldırır.

## Demo

Tek komutla izole test ortamı kurar, trafik üretir, sonuçları gösterir:

```bash
make
sudo ./scripts/demo.sh
```

## Test ortamı

`veth` çifti + network namespace ile izole ortam. Gerçek arayüze
dokunulmadığı için hatalı kural ağ bağlantısını kesmez.

```bash
sudo ./scripts/testenv.sh up      # 10.10.0.1 <-> 10.10.0.2
sudo ./xdpfw veth0
sudo ip netns exec xdptest ping 10.10.0.1
sudo ./scripts/testenv.sh down
```

## Mimari
BPF programı her pakette Ethernet ve IPv4 başlıklarını ayrıştırır,
protokolü tespit eder ve ilgili sayacı artırır. Sayaçlar per-CPU
tutulur (kilitsiz artış); kullanıcı alanı okurken CPU'ları toplar.
```
NIC surucusu --> XDP programi --> XDP_PASS --> kernel ag yigini
                      |
                      v
              PERCPU_ARRAY (stats)
                      |
                      v
              kullanici alani CLI
```
## Dosya yapısı

| Dosya | Açıklama |
|---|---|
| `src/xdpfw.bpf.c` | Kernel'de çalışan XDP programı |
| `src/xdpfw.c` | Yükleyici + istatistik gösterimi |
| `src/xdpfw.h` | BPF ve kullanıcı alanının paylaştığı tipler |
| `src/vmlinux.h` | bpftool'un ürettiği kernel tipleri (git'te tutulmaz) |
| `src/xdpfw.skel.h` | bpftool'un ürettiği skeleton (git'te tutulmaz) |
| `scripts/testenv.sh` | veth + netns test ortamı |
| `scripts/demo.sh` | Uçtan uca demo |

## Hata ayıklama

```bash
XDPFW_DEBUG=1 sudo ./xdpfw veth0      # verifier logu
sudo bpftool net show                 # hangi arayüzde ne bağlı
sudo bpftool prog show                # yüklü programlar
sudo bpftool map dump name stats       # map'in ham içeriği
```

## Bilinen sınırlar

- Yalnızca IPv4 (IPv6 desteklenmiyor)
- Bir arayüze aynı anda tek XDP programı bağlanabilir (`libxdp`
  dispatcher kullanılmıyor); ikinci yükleme `-EBUSY` verir
- IP fragmentasyonu dikkate alınmıyor
