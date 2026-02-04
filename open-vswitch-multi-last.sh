#!/bin/bash
set -e

cat <<EOF >> /etc/network/interfaces

# ===== Open vSwitch configuration (prox oobm) =====

auto prox_oobm
iface prox_oobm inet manual
    ovs_type OVSBridge
    address 172.30.0.100/24
    
# ===== End Open vSwitch configuration (prox oobm) =====
EOF


echo "Reloading network configuration..."
ifreload -a

echo "Open vSwitch status:"
ovs-vsctl show

echo "Open vSwitch post-setup complete."
