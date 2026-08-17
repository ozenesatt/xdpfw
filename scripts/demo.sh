#!/usr/bin/env bash
# xdpfw uctan uca demo
set -euo pipefail

cd "$(dirname "$0")/.."

[ "$EUID" -eq 0 ] || { echo "Root gerekir: sudo $0" >&2; exit 1; }
[ -x ./xdpfw ]    || { echo "./xdpfw yok. Once 'make' calistir." >&2; exit 1; }

BEKLE() { echo; sleep 1.5; }

cleanup() {
    ./xdpfw unload veth0 2>/dev/null || true
    rm -rf /sys/fs/bpf/xdpfw
    ./scripts/testenv.sh down 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 1/7  Izole test ortami kuruluyor ==="
./scripts/testenv.sh down 2>/dev/null || true
rm -rf /sys/fs/bpf/xdpfw
./scripts/testenv.sh up
BEKLE

echo "=== 2/7  XDP programi yukleniyor ==="
./xdpfw load veth0
bpftool net show | grep veth0
BEKLE

echo "=== 3/7  Kural dosyasi yukleniyor ==="
./xdpfw reload rules.conf
BEKLE

echo "=== 4/7  Trafik uretiliyor ==="
echo "  ICMP (10.10.0.2 -> engelli olmali)"
ip netns exec xdptest ping -c3 -W1 10.10.0.1 2>&1 | tail -2 || true
echo
echo "  ICMP (10.10.0.3 -> gecmeli)"
ip netns exec xdptest ping -c3 -I 10.10.0.3 10.10.0.1 2>&1 | tail -2 || true
echo
echo "  UDP port 53 (10.10.0.3 -> port kuraliyla engellenmeli)"
ip netns exec xdptest bash -c 'echo x | timeout 2 nc -u -s 10.10.0.3 -p 5353 10.10.0.1 53' >/dev/null 2>&1 || true
echo "  gonderildi"
BEKLE

echo "=== 5/7  Kural eslesmeleri ==="
./xdpfw list
BEKLE

echo "=== 6/7  En cok paket gonderen kaynaklar ==="
./xdpfw top 5
BEKLE

echo "=== 7/7  Sayaclar ==="
timeout 2 ./xdpfw stats 1 2>/dev/null | head -14 || true

echo
echo "=== Demo tamamlandi, temizleniyor ==="
