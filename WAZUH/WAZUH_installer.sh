#!/bin/bash
set -e

# -----------------------------
# CONFIG
# -----------------------------
VMID=150
VMNAME="wazuh"
OVA_URL="https://packages.wazuh.com/4.9/ova/wazuh-4.9.0.ova"

STORAGE="local-lvm"
BRIDGE1="vmbr0"
BRIDGE2="vmbr1"

CPU_CORES=4
RAM_MB=8192

WORKDIR="/tmp/wazuh-ova"
CI_SNIPPET="/var/lib/vz/snippets/wazuh-userdata.yaml"
# -----------------------------

mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "➡ Downloading Wazuh OVA..."
wget -q --show-progress -O wazuh.ova "$OVA_URL"

echo "➡ Extracting OVA..."
tar -xf wazuh.ova

OVF_FILE=$(ls *.ovf | head -n 1)

if [[ ! -f "$OVF_FILE" ]]; then
  echo "❌ OVF not found — aborting"
  exit 1
fi

echo "➡ Creating VM $VMID..."
qm create "$VMID" \
  --name "$VMNAME" \
  --cores "$CPU_CORES" \
  --memory "$RAM_MB" \
  --scsihw virtio-scsi-pci \
  --net0 virtio,bridge="$BRIDGE1" \
  --net1 virtio,bridge="$BRIDGE2"

echo "➡ Importing OVF..."
qm importovf "$VMID" "$OVF_FILE" "$STORAGE" --format qcow2

echo "➡ Attaching disk..."
qm set "$VMID" --scsi0 "$STORAGE:vm-$VMID-disk-0"

echo "➡ Setting boot options..."
qm set "$VMID" --boot c --bootdisk scsi0

echo "➡ Adding cloud-init disk..."
qm set "$VMID" --ide2 "$STORAGE":cloudinit
qm set "$VMID" --serial0 socket --vga serial0

echo "➡ Creating cloud-init user-data..."
mkdir -p "$(dirname "$CI_SNIPPET")"

cat > "$CI_SNIPPET" <<EOF
#cloud-config
hostname: wazuh
manage_etc_hosts: true

users:
  - name: ec2-user
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: []
ssh_pwauth: false

network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses:
        - 192.168.2.20/24
      gateway4: 192.168.20.1
    eth1:
      dhcp4: false
      addresses:
        - 172.20.0.20/24
      routes:
        - to: 0.0.0.0/0
          via: 192.168.20.1
nameservers:
  addresses: [1.1.1.1, 8.8.8.8]

runcmd:
  - systemctl enable wazuh-manager || true
  - systemctl restart wazuh-manager || true
EOF

echo "➡ Attaching custom cloud-init config..."
qm set "$VMID" --cicustom "user=local:snippets/$(basename "$CI_SNIPPET")"

echo "➡ Done — starting VM..."
qm start "$VMID"

echo
echo "✔ Wazuh VM created"
echo "   VMID: $VMID"
echo "   Name: $VMNAME"
echo "   NIC1: 192.168.2.20/24 (gw 192.168.20.1)"
echo "   NIC2: 172.20.0.20/24"
