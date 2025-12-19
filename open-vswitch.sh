#!/bin/bash
set -e

### VARIABLES (EDIT THESE) ###
BRIDGE="lan1"

### CHECK ROOT ###
if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "Installing Open vSwitch..."
apt update
apt install -y openvswitch-switch ifupdown2

systemctl enable --now openvswitch-switch

echo "Backing up network config..."
cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%F_%T)

echo "Writing OVS network configuration..."

cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $NIC
iface $NIC inet manual
    ovs_type OVSPort
    ovs_bridge $BRIDGE

auto $BRIDGE
iface $BRIDGE inet static
    ovs_type OVSBridge
EOF

echo "Reloading network configuration..."
ifreload -a

echo "OVS configuration complete."
echo "Verifying:"
ovs-vsctl show
ip addr show $BRIDGE
