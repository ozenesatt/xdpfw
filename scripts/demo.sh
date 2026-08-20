#!/usr/bin/env bash
# xdpfw uctan uca demo
set -euo pipefail

cd "$(dirname "$0")/.."

[ "$EUID" -eq 0 ] || { echo "Root gerekir: sudo $0" >&2; exit 1; }
[ -x ./xdpfw ]    || { echo "./xdpfw yok. Once 'make' calistir." >&2; exit 1; }

XF=./xdpfw
BEKLE() { echo; sleep 1.2; }

cleanup() {
    $XF durdur veth0 2>/dev/null || true
    rm -rf /sys/fs/bpf/xdpfw
    ./scripts/testenv.sh down 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 1/8  Izole test ortami ==="
./scripts/testenv.sh down 2>/dev/null || true
rm -rf /sys/fs/bpf/xdpfw
./scripts/testenv.sh up
BEKLE

echo "=== 2/8  XDP programi yukleniyor ==="
$XF basla veth0
bpftool net show | grep veth0
BEKLE

echo "=== 3/8  Kaynak IP kurali ==="
$XF engelle 10.10.0.2
echo "  10.10.0.2 -> engelli olmali"
ip netns exec xdptest ping -c2 -W1 10.10.0.1 2>&1 | tail -2 || true
echo "  10.10.0.3 -> gecmeli"
ip netns exec xdptest ping -c2 -I 10.10.0.3 10.10.0.1 2>&1 | tail -2 || true
$XF kaldir 10.10.0.2
BEKLE

echo "=== 4/8  Bilesik kural (IP + port) ==="
$XF engelle-akis 10.10.0.2 tcp 9999
echo "  10.10.0.2 -> tcp/9999 (engelli)"
ip netns exec xdptest bash -c 'timeout 2 nc -s 10.10.0.2 10.10.0.1 9999' 2>/dev/null || true
echo "  10.10.0.2 -> tcp/8888 (gecmeli, ayni IP farkli port)"
ip netns exec xdptest bash -c 'timeout 2 nc -s 10.10.0.2 10.10.0.1 8888' 2>/dev/null || true
$XF kurallar | grep -A2 "akislar"
$XF kaldir-akis 10.10.0.2 tcp 9999
BEKLE

echo "=== 5/8  Port araligi ==="
$XF engelle-aralik tcp 8000 9000
echo "  tcp/8500 (aralik icinde, engelli)"
ip netns exec xdptest bash -c 'timeout 2 nc -s 10.10.0.2 10.10.0.1 8500' 2>/dev/null || true
echo "  tcp/7000 (aralik disinda, gecmeli)"
ip netns exec xdptest bash -c 'timeout 2 nc -s 10.10.0.2 10.10.0.1 7000' 2>/dev/null || true
$XF kurallar | grep -A2 "Port araliklari"
$XF kaldir-aralik tcp 8000 9000
BEKLE

echo "=== 6/8  Hiz siniri (token bucket) ==="
$XF hiz-sinir 10.10.0.2 100 200
echo "  3 saniyelik paket seli, limit 100 pkt/sn..."
ip netns exec xdptest timeout 3 hping3 --flood --udp -p 7777 10.10.0.1 > /dev/null 2>&1 || true
$XF kurallar | grep -A2 "Hiz sinirlari"
BEKLE

echo "=== 7/8  Kural eslesmeleri ve top talkers ==="
$XF kurallar | grep -v "(yok)" | grep -v "^$"
echo
$XF zirve 5
BEKLE

echo "=== 8/8  Sayaclar ==="
timeout 2 $XF durum 1 2>/dev/null | head -16 || true

echo
echo "=== Demo tamamlandi, temizleniyor ==="
