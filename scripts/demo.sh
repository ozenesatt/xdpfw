#!/usr/bin/env bash
# Uctan uca demo: ortam -> yukle -> trafik -> kural -> engelleme -> temizlik
set -euo pipefail

cd "$(dirname "$0")/.."

[ "$EUID" -eq 0 ] || { echo "Root gerekir: sudo $0" >&2; exit 1; }
[ -x ./xdpfw ]    || { echo "./xdpfw yok. Once 'make' calistir." >&2; exit 1; }

cleanup() {
    ./xdpfw unload veth0 2>/dev/null || true
    rm -rf /sys/fs/bpf/xdpfw
    ./scripts/testenv.sh down 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 1/6  Test ortami ==="
./scripts/testenv.sh down 2>/dev/null || true
rm -rf /sys/fs/bpf/xdpfw
./scripts/testenv.sh up

echo
echo "=== 2/6  XDP programi yukleniyor ==="
./xdpfw load veth0
bpftool net show | grep -q veth0 || { echo "HATA: bagli degil" >&2; exit 1; }

echo
echo "=== 3/6  Kuralsiz trafik ==="
ip netns exec xdptest ping -c3 10.10.0.1 | tail -2

echo
echo "=== 4/6  Kural ekleniyor ==="
./xdpfw block-ip 10.10.0.2
./xdpfw block-port tcp 9999

echo
echo "=== 5/6  Kurali trafik (engellenmeli) ==="
ip netns exec xdptest ping -c3 -W1 10.10.0.1 | tail -2 || true

echo
echo "--- Kural eslesmeleri ---"
./xdpfw list

echo
echo "--- Sayaclar ---"
timeout 2 ./xdpfw stats 1 2>/dev/null | head -12 || true

echo
echo "=== 6/6  Temizleniyor ==="
