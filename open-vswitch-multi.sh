#!/bin/bash
set -e


### VARIABLES (EDIT THESE) ###
BRIDGE1=""
BRIDGE2=""
BRIDGE3=""

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
   
# ===== End Open vSwitch configuration =====
EOF
