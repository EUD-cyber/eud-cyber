#!/bin/bash
set -e

### VARIABLES (EDIT THESE) ###
BRIDGE1=""
BRIDGE2=""
BRIDGE3=""

### CHECK ROOT ###
if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

systemctl enable --now openvswitch-switch

echo "Backing up network config..."
cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%F_%T)

# this downloads the public key so that the app.py can look at the openvswitch config in the guacvm
wget -qO- https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/SSHKEYS/shared_admin_ed25519.pub >> /root/.ssh/authorized_keys


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
