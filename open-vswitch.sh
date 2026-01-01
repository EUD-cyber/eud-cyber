#!/bin/bash
set -e

### VARIABLES (EDIT THESE) ###
BRIDGE1="lan1"
BRIDGE2="lan2"
BRIDGE3="oobm"

### CHECK ROOT ###
if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

systemctl enable --now openvswitch-switch

echo "Backing up network config..."
cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%F_%T)

echo "Appending OVS configuration..."

cat <<EOF >> /etc/network/interfaces

# ===== Open vSwitch configuration =====

auto $BRIDGE1
iface $BRIDGE1 inet static
    ovs_type OVSBridge

auto $BRIDGE2
iface $BRIDGE2 inet static
    ovs_type OVSBridge

auto $BRIDGE3
iface $BRIDGE3 inet static
    ovs_type OVSBridge
    address 172.20.0.100/24

# ===== End Open vSwitch configuration =====
EOF

echo "Reloading network configuration..."
ifreload -a

echo "OVS configuration complete."
ovs-vsctl show
