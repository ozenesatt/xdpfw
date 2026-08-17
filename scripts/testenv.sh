#!/usr/bin/env bash
# veth cifti + network namespace ile izole test ortami
set -euo pipefail

NS=xdptest
HOST_IF=veth0
PEER_IF=veth1
HOST_IP=10.10.0.1/24
PEER_IP=10.10.0.2/24

up() {
    ip netns add "$NS"
    ip link add "$HOST_IF" type veth peer name "$PEER_IF"
    ip link set "$PEER_IF" netns "$NS"

    ip addr add "$HOST_IP" dev "$HOST_IF"
    ip link set "$HOST_IF" up

    ip netns exec "$NS" ip addr add "$PEER_IP" dev "$PEER_IF"
    ip netns exec "$NS" ip link set "$PEER_IF" up
    ip netns exec "$NS" ip link set lo up

    ethtool -K "$HOST_IF" gro off 2>/dev/null || true

    echo "Hazir. Host: ${HOST_IP%/*}  |  Namespace '$NS': ${PEER_IP%/*}"
}

down() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    echo "Test ortami temizlendi."
}

case "${1:-}" in
    up)   up ;;
    down) down ;;
    *)    echo "Kullanim: $0 {up|down}" >&2; exit 1 ;;
esac
