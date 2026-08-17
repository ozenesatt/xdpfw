#!/usr/bin/env bash
# Basit yuk testi: hping3 ile paket akisi uret, XDP sayaclarindan pps oku
set -euo pipefail

cd "$(dirname "$0")/.."

[ "$EUID" -eq 0 ] || { echo "Root gerekir: sudo $0" >&2; exit 1; }

SURE=${1:-10}   # saniye

# stats map'inden toplam paket sayisini oku (tum CPU'lar toplanmis)
oku_toplam() {
    bpftool map dump name stats -p 2>/dev/null | python3 -c '
import json, sys
def coz(b): return int.from_bytes(bytes(int(x,16) for x in b), "little")
for e in json.load(sys.stdin):
    if coz(e["key"]) == 0:          # STAT_TOTAL
        print(sum(coz(v["value"]) for v in e["values"]))
        break
' 2>/dev/null || echo 0
}

echo "Sure: ${SURE} sn"
echo

BAS=$(oku_toplam)
ip netns exec xdptest timeout "$SURE" hping3 --flood --udp -p 9999 10.10.0.1 \
    > /dev/null 2>&1 || true
SON=$(oku_toplam)

FARK=$((SON - BAS))
PPS=$((FARK / SURE))

printf "Islenen paket : %d\n" "$FARK"
printf "Ortalama pps  : %d\n" "$PPS"
