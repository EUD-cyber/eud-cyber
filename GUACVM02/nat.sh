#!/usr/bin/env bash
set -Eeuo pipefail

EXTERNAL_IF="eth0"
LAB_IF="ens19"
LAB_SOURCE_IP="192.168.10.1"

NAT_CHAIN="CYBERLAB_DNAT"
SNAT_CHAIN="CYBERLAB_SNAT"
FORWARD_CHAIN="CYBERLAB_FORWARD"

# Format:
# "EXTERNAL_PORT DESTINATION_IP DESTINATION_PORT NAME"
NAT_RULES=(
  "3001 192.168.10.2 443 FMG"
  "3002 192.168.10.3 443 FAZ"
  "3003 192.168.10.4 443 FGT"
  "3004 192.168.10.5 443 WAZUH"
  "3005 192.168.10.6 443 ADVPN-FGT01"
  "3006 192.168.10.7 443 ADVPN-FGT02"
)

log() {
  printf '[+] %s\n' "$*"
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ $EUID -eq 0 ]] || die "Run with sudo or as root."
}

check_interface() {
  local interface="$1"

  ip link show "$interface" >/dev/null 2>&1 ||
    die "Interface $interface does not exist."
}

get_external_ip() {
  EXTERNAL_IP="$(
    ip -4 -o addr show dev "$EXTERNAL_IF" scope global |
      awk '{print $4}' |
      cut -d/ -f1 |
      head -n1
  )"

  [[ -n "$EXTERNAL_IP" ]] ||
    die "No IPv4 address found on $EXTERNAL_IF."
}

check_lab_ip() {
  ip -4 addr show dev "$LAB_IF" |
    grep -qE "[[:space:]]inet[[:space:]]${LAB_SOURCE_IP//./\\.}/" ||
    die "$LAB_SOURCE_IP is not configured on $LAB_IF."
}

enable_forwarding() {
  cat >/etc/sysctl.d/99-cyberlab-nat.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL

  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

delete_jump_rules() {
  while iptables -t nat -C PREROUTING \
    -i "$EXTERNAL_IF" \
    -j "$NAT_CHAIN" 2>/dev/null; do

    iptables -t nat -D PREROUTING \
      -i "$EXTERNAL_IF" \
      -j "$NAT_CHAIN"
  done

  while iptables -t nat -C POSTROUTING \
    -o "$LAB_IF" \
    -j "$SNAT_CHAIN" 2>/dev/null; do

    iptables -t nat -D POSTROUTING \
      -o "$LAB_IF" \
      -j "$SNAT_CHAIN"
  done

  while iptables -C FORWARD \
    -j "$FORWARD_CHAIN" 2>/dev/null; do

    iptables -D FORWARD \
      -j "$FORWARD_CHAIN"
  done
}

delete_chains() {
  iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
  iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true

  iptables -t nat -F "$SNAT_CHAIN" 2>/dev/null || true
  iptables -t nat -X "$SNAT_CHAIN" 2>/dev/null || true

  iptables -F "$FORWARD_CHAIN" 2>/dev/null || true
  iptables -X "$FORWARD_CHAIN" 2>/dev/null || true
}

create_rules() {
  iptables -t nat -N "$NAT_CHAIN"
  iptables -t nat -N "$SNAT_CHAIN"
  iptables -N "$FORWARD_CHAIN"

  local external_port
  local destination_ip
  local destination_port
  local name

  for rule in "${NAT_RULES[@]}"; do
    read -r external_port destination_ip destination_port name <<<"$rule"

    log "$name: ${EXTERNAL_IP}:${external_port} -> ${destination_ip}:${destination_port}"

    iptables -t nat -A "$NAT_CHAIN" \
      -p tcp \
      -d "$EXTERNAL_IP" \
      --dport "$external_port" \
      -j DNAT \
      --to-destination "${destination_ip}:${destination_port}"

    iptables -t nat -A "$SNAT_CHAIN" \
      -p tcp \
      -d "$destination_ip" \
      --dport "$destination_port" \
      -j SNAT \
      --to-source "$LAB_SOURCE_IP"

    iptables -A "$FORWARD_CHAIN" \
      -i "$EXTERNAL_IF" \
      -o "$LAB_IF" \
      -p tcp \
      -d "$destination_ip" \
      --dport "$destination_port" \
      -m conntrack \
      --ctstate NEW,ESTABLISHED,RELATED \
      -j ACCEPT

    iptables -A "$FORWARD_CHAIN" \
      -i "$LAB_IF" \
      -o "$EXTERNAL_IF" \
      -p tcp \
      -s "$destination_ip" \
      --sport "$destination_port" \
      -m conntrack \
      --ctstate ESTABLISHED,RELATED \
      -j ACCEPT
  done

  iptables -t nat -A "$NAT_CHAIN" -j RETURN
  iptables -t nat -A "$SNAT_CHAIN" -j RETURN
  iptables -A "$FORWARD_CHAIN" -j RETURN

  iptables -t nat -I PREROUTING 1 \
    -i "$EXTERNAL_IF" \
    -j "$NAT_CHAIN"

  iptables -t nat -I POSTROUTING 1 \
    -o "$LAB_IF" \
    -j "$SNAT_CHAIN"

  iptables -I FORWARD 1 \
    -j "$FORWARD_CHAIN"
}

save_rules() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null
    log "Rules saved with netfilter-persistent."
  else
    log "Rules are active but not persistent."
  fi
}

apply_rules() {
  require_root

  check_interface "$EXTERNAL_IF"
  check_interface "$LAB_IF"

  get_external_ip
  check_lab_ip
  enable_forwarding

  log "External interface: $EXTERNAL_IF"
  log "External IP: $EXTERNAL_IP"
  log "Lab interface: $LAB_IF"
  log "Lab source IP: $LAB_SOURCE_IP"

  log "Removing old Cyberlab NAT rules."
  delete_jump_rules
  delete_chains

  log "Creating new Cyberlab NAT rules."
  create_rules
  save_rules

  log "NAT applied successfully."
}

remove_rules() {
  require_root

  log "Removing Cyberlab NAT rules."

  delete_jump_rules
  delete_chains

  rm -f /etc/sysctl.d/99-cyberlab-nat.conf

  save_rules

  log "NAT removed."
}

show_status() {
  require_root

  check_interface "$EXTERNAL_IF"
  check_interface "$LAB_IF"
  get_external_ip

  echo "=== Interfaces ==="
  ip -br -4 address show "$EXTERNAL_IF" "$LAB_IF" || true

  echo
  echo "=== Detected external IP ==="
  echo "$EXTERNAL_IP"

  echo
  echo "=== IPv4 forwarding ==="
  sysctl net.ipv4.ip_forward

  echo
  echo "=== DNAT rules ==="
  iptables -t nat -L "$NAT_CHAIN" \
    -n -v --line-numbers 2>/dev/null ||
    echo "DNAT chain does not exist."

  echo
  echo "=== SNAT rules ==="
  iptables -t nat -L "$SNAT_CHAIN" \
    -n -v --line-numbers 2>/dev/null ||
    echo "SNAT chain does not exist."

  echo
  echo "=== Forward rules ==="
  iptables -L "$FORWARD_CHAIN" \
    -n -v --line-numbers 2>/dev/null ||
    echo "Forward chain does not exist."
}

case "${1:-}" in
  apply)
    apply_rules
    ;;
  remove)
    remove_rules
    ;;
  status)
    show_status
    ;;
  *)
    echo "Usage: sudo $0 {apply|status|remove}"
    exit 1
    ;;
esac
