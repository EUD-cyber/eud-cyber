#!/bin/bash
set -e

PROXOOBM="prox_oobm"

auto 
iface $PROXOOBM inet manual
    ovs_type OVSBridge
    address 172.30.0.100/24

echo "Reloading network configuration..."
ifreload -a

echo "Open vSwitch status:"
ovs-vsctl show

echo "Open vSwitch post-setup complete."
