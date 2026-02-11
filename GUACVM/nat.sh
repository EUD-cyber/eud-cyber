#!/bin/bash
set -euo pipefail

echo ">>> Enable IPv4 forwarding"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-lab-ipforward.conf
sysctl -p /etc/sysctl.d/99-lab-ipforward.conf

# ============================
# INTERFACES
# ============================
ETH_OUT="eth0"      # WAN
ETH_LAB="eth1"      # 172.20.0.0/24
ETH_LAB2="eth2"     # 172.30.0.0/24

GUAC_LAB_IP="172.20.0.1"
GUAC_LAB2_IP=$(ip -4 addr show "$ETH_LAB2" | awk '/inet / {print $2}' | cut -d/ -f1)

# ============================
# IMPORTANT: DO NOT FLUSH IPTABLES
# ============================

# Ensure Docker forwarding works
iptables -P FORWARD ACCEPT

# Allow established traffic (safe to re-add if missing)
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# ============================
# FUNCTION TO ADD RULE SAFELY
# ============================
add_rule() {
  if ! iptables "$@" 2>/dev/null; then
    iptables "$@"
  fi
}

# ============================
# PROXMOX (172.30.0.100 via 9001)
# ============================

PROXMOX_IP="172.30.0.100"
PROXMOX_PORT=8006
PROXMOX_OUTSIDE=9001

echo ">>> NAT: Proxmox"

iptables -t nat -C PREROUTING -i $ETH_OUT -p tcp --dport $PROXMOX_OUTSIDE \
  -j DNAT --to-destination $PROXMOX_IP:$PROXMOX_PORT 2>/dev/null \
  || iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $PROXMOX_OUTSIDE \
  -j DNAT --to-destination $PROXMOX_IP:$PROXMOX_PORT

iptables -t nat -C POSTROUTING -o $ETH_LAB2 -d $PROXMOX_IP -p tcp --dport $PROXMOX_PORT \
  -j SNAT --to-source $GUAC_LAB2_IP 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o $ETH_LAB2 -d $PROXMOX_IP -p tcp --dport $PROXMOX_PORT \
  -j SNAT --to-source $GUAC_LAB2_IP

iptables -C FORWARD -i $ETH_OUT -o $ETH_LAB2 -p tcp --dport $PROXMOX_PORT -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i $ETH_OUT -o $ETH_LAB2 -p tcp --dport $PROXMOX_PORT -j ACCEPT

# ============================
# WAZUH (172.20.0.20 via 9002)
# ============================

WAZUH_IP="172.20.0.20"
WAZUH_PORT=443
WAZUH_OUTSIDE=9002

echo ">>> NAT: Wazuh"

iptables -t nat -C PREROUTING -i $ETH_OUT -p tcp --dport $WAZUH_OUTSIDE \
  -j DNAT --to-destination $WAZUH_IP:$WAZUH_PORT 2>/dev/null \
  || iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $WAZUH_OUTSIDE \
  -j DNAT --to-destination $WAZUH_IP:$WAZUH_PORT

iptables -t nat -C POSTROUTING -o $ETH_LAB -d $WAZUH_IP -p tcp --dport $WAZUH_PORT \
  -j SNAT --to-source $GUAC_LAB_IP 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o $ETH_LAB -d $WAZUH_IP -p tcp --dport $WAZUH_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -C FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $WAZUH_PORT -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $WAZUH_PORT -j ACCEPT

# ============================
# OPNsense (172.20.0.2 via 9003)
# ============================

OPNSENSE_IP="172.20.0.2"
OPNSENSE_PORT=443
OPNSENSE_OUTSIDE=9003

echo ">>> NAT: OPNsense"

iptables -t nat -C PREROUTING -i $ETH_OUT -p tcp --dport $OPNSENSE_OUTSIDE \
  -j DNAT --to-destination $OPNSENSE_IP:$OPNSENSE_PORT 2>/dev/null \
  || iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $OPNSENSE_OUTSIDE \
  -j DNAT --to-destination $OPNSENSE_IP:$OPNSENSE_PORT

iptables -t nat -C POSTROUTING -o $ETH_LAB -d $OPNSENSE_IP -p tcp --dport $OPNSENSE_PORT \
  -j SNAT --to-source $GUAC_LAB_IP 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o $ETH_LAB -d $OPNSENSE_IP -p tcp --dport $OPNSENSE_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -C FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $OPNSENSE_PORT -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $OPNSENSE_PORT -j ACCEPT

echo ">>> NAT configuration complete."
