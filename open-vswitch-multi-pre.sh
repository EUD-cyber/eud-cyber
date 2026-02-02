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

echo "Preparing SSH access for Guacamole..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh
wget -qO- https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/SSHKEYS/shared_admin_ed25519.pub \
  >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

echo "Open vSwitch pre-setup complete."
