#!/usr/bin/env bash
# Tek komutluk demo: ortam kur -> yukle -> trafik uret -> istatistik -> temizle
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$EUID" -ne 0 ]; then
    echo "Bu script root gerektirir: sudo $0" >&2
    exit 1
fi

if [ ! -x ./xdpfw ]; then
    echo "HATA: ./xdpfw bulunamadi. Once 'make' calistir." >&2
    exit 1
fi

echo "=== 1/5  Test ortami kuruluyor ==="
./scripts/testenv.sh down 2>/dev/null || true
./scripts/testenv.sh up

echo
echo "=== 2/5  XDP programi yukleniyor ==="
./xdpfw veth0 > /dev/null &
XDPFW_PID=$!
sleep 2

cleanup() {
    kill -INT $XDPFW_PID 2>/dev/null || true
    sleep 1
    ./scripts/testenv.sh down 2>/dev/null || true
}
trap cleanup EXIT

if ! kill -0 $XDPFW_PID 2>/dev/null; then
    echo "HATA: xdpfw baslatilmadi." >&2
    exit 1
fi
bpftool net show | grep -q veth0 || { echo "HATA: XDP bagli degil." >&2; exit 1; }
echo "  veth0 arayuzune baglandi (native XDP)."

echo
echo "=== 3/5  Trafik uretiliyor ==="
ip netns exec xdptest ping -c5 10.10.0.1 > /dev/null
echo "  ICMP: 5 paket"

nc -l -p 9999 > /dev/null &
NC_PID=$!
sleep 1
ip netns exec xdptest bash -c 'echo test | timeout 2 nc 10.10.0.1 9999' > /dev/null || true
kill $NC_PID 2>/dev/null || true
echo "  TCP:  1 baglanti"

ip netns exec xdptest bash -c 'echo test | timeout 2 nc -u 10.10.0.1 9999' > /dev/null || true
echo "  UDP:  1 datagram"

echo
echo "=== 4/5  Sayaclar (tum CPU'lar toplanmis) ==="
bpftool map dump name stats -p | python3 -c '
import json, sys

def coz(baytlar):
    # bpftool -p little-endian hex string listesi veriyor: ["0x08","0x00",...]
    return int.from_bytes(bytes(int(b, 16) for b in baytlar), "little")

adlar = ["Toplam paket", "TCP", "UDP", "ICMP", "Diger"]
for e in json.load(sys.stdin):
    idx = coz(e["key"])
    toplam = sum(coz(v["value"]) for v in e["values"])
    print("  %-14s %d" % (adlar[idx], toplam))
'

echo
echo "=== 5/5  Demo tamamlandi, temizleniyor ==="
