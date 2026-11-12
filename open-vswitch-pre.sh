#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "Enabling Open vSwitch..."
systemctl enable --now openvswitch-switch

echo "Backing up network config..."
cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%F_%T)

echo "Open vSwitch pre-setup complete."
