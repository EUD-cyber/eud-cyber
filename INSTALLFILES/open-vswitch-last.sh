#!/bin/bash
set -e

echo "Reloading network configuration..."
ifreload -a

echo "Open vSwitch status:"
ovs-vsctl show

echo "Open vSwitch post-setup complete."
