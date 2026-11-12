#!/bin/bash
set -e

LAB="$1"

if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  exit 1
fi

BRIDGE1="lab${LAB}_lan1"
BRIDGE2="lab${LAB}_lan2"
BRIDGE3="lab${LAB}_oobm"

# Prevent duplicates
if grep -q "auto $BRIDGE1" /etc/network/interfaces; then
  echo "OVS bridges for lab $LAB already exist, skipping."
  exit 0
fi

echo "Appending OVS configuration for lab $LAB..."

cat <<EOF >> /etc/network/interfaces

# ===== Open vSwitch configuration (Lab $LAB) =====

auto $BRIDGE1
iface $BRIDGE1 inet manual
    ovs_type OVSBridge

auto $BRIDGE2
iface $BRIDGE2 inet manual
    ovs_type OVSBridge

auto $BRIDGE3
iface $BRIDGE3 inet manual
    ovs_type OVSBridge

# ===== End Open vSwitch configuration (Lab $LAB) =====
EOF
