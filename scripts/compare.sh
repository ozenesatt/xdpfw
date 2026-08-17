#!/usr/bin/env bash
# iptables vs nftables vs XDP karsilastirmasi
# Metrik: sabit sayida paket gonderiminin ALICI tarafta yarattigi CPU yuku
set -uo pipefail

cd "$(dirname "$0")/.."
[ "$EUID" -eq 0 ] || { echo "Root gerekir: sudo $0" >&2; exit 1; }

SURE=${1:-10}
IF=veth0

temizle() {
    ./xdpfw unload $IF 2>/dev/null || true
    rm -rf /sys/fs/bpf/xdpfw
    iptables -F INPUT 2>/dev/null || true
    nft delete table ip xdpfw_test 2>/dev/null || true
    sleep 1
}

# /proc/stat'tan softirq+system jiffy oku (paket isleme burada gorunur)
cpu_oku() {
    awk '/^cpu /{print $4+$7+$8}' /proc/stat   # system + irq + softirq
}

olc() {
    local ad="$1" c1 c2 rx1 rx2 jiffy paket

    sleep 1
    c1=$(cpu_oku)
    rx1=$(cat /sys/class/net/$IF/statistics/rx_packets)

    ip netns exec xdptest timeout "$SURE" hping3 --flood --udp -p 9999 10.10.0.1 \
        > /dev/null 2>&1 || true

    c2=$(cpu_oku)
    rx2=$(cat /sys/class/net/$IF/statistics/rx_packets)

    jiffy=$((c2 - c1))
    paket=$((rx2 - rx1))

    # paket basina CPU maliyeti (jiffy/milyon paket)
    if [ "$paket" -gt 0 ]; then
        printf "%-22s %12d %10d %14d\n" "$ad" "$paket" "$jiffy" \
               "$(echo "scale=4; $jiffy * 1000000 / $paket" | bc)"
    else
        printf "%-22s %12d %10d %14s\n" "$ad" "$paket" "$jiffy" "-"
    fi
}

temizle
echo "Sure: ${SURE} sn / yapilandirma"
echo
printf "%-22s %12s %10s %14s\n" "YAPILANDIRMA" "PAKET" "CPU(jiffy)" "JIFFY/M.PAKET"
echo "----------------------------------------------------------------"

olc "1. Filtresiz"

iptables -A INPUT -i $IF -p udp --dport 9999 -j DROP
olc "2. iptables DROP"
iptables -F INPUT

nft add table ip xdpfw_test 2>/dev/null
nft add chain ip xdpfw_test input "{ type filter hook input priority 0; }" 2>/dev/null
nft add rule ip xdpfw_test input udp dport 9999 drop 2>/dev/null
olc "3. nftables drop"
nft delete table ip xdpfw_test 2>/dev/null

./xdpfw load $IF > /dev/null
./xdpfw block-port udp 9999 > /dev/null
olc "4. XDP DROP"

echo
echo "Dusuk JIFFY/M.PAKET = daha verimli (paket basina daha az CPU)"
temizle
