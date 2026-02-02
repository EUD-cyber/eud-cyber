#!/bin/bash
set -e

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

echo "Reloading network configuration..."
ifreload -a

echo "OVS configuration complete."
ovs-vsctl show
