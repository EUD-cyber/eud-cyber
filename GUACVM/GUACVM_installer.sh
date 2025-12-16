#!/bin/bash
set -e

# ===== CONFIG =====
START_VMID=100
BASE_NAME="GUACVM"
IMG_URL="https://cloud-images.ubuntu.com/noble/20251213/noble-server-cloudimg-amd64.img"
IMG_NAME="noble-server-cloudimg-amd64.img"
IMG_PATH="$(pwd)/$IMG_NAME"
ISO_STORAGE="local"
DISK_STORAGE="local-lvm"
MEMORY=4096       # in MB
CORES=4
DISK_SIZE="32"    # the number is in GB
BRIDGE="vmbr0"
# ==================

# Ask user for network type
echo "Select network configuration:"
echo "1) DHCP"
echo "2) Static"
read -p "Enter choice [1-2]: " choice

if [ "$choice" == "1" ]; then
    IP_ADDR=dhcp
    DNS_SERVER=""
EOF
)
elif [ "$choice" == "2" ]; then
    read -p "Enter static IP (e.g., 192.168.1.100/24): " STATIC_IP
    read -p "Enter gateway (e.g., 192.168.1.1): " GATEWAY
    read -p "Enter DNS servers (comma separated, e.g., 8.8.8.8,1.1.1.1): " DNS
    IP_ADDR=$STATIC_IP,gw=$GATEWAY
    DNS_SERVER=$DNS

# ===== Find next free VMID =====
VMID=$START_VMID
while qm status $VMID &>/dev/null; do
    VMID=$((VMID + 1))
done
echo "Selected free VMID: $VMID"

# ===== Handle VM name collision =====
VM_NAME="$BASE_NAME"
COUNT=1
while qm list | awk '{print $2}' | grep -x "$VM_NAME" &>/dev/null; do
    VM_NAME="${BASE_NAME}-${COUNT}"
    COUNT=$((COUNT + 1))
done
echo "VM name to use: $VM_NAME"

# ===== Download IMG if missing =====
if [ ! -f "$IMG_PATH" ]; then
    echo "Downloading $IMG_NAME IMG..."
    wget --show-progress -O "$IMG_PATH" "$IMG_URL"
else
    echo "IMG already exists: $IMG_PATH"
fi

# ===== Create VM =====
echo "Creating VM $VMID..."
qm create $VMID \
  --name "$VM_NAME" \
  --memory $MEMORY \
  --cores $CORES \
  --cpu host \
  --net0 virtio,bridge=$BRIDGE \
  --ostype l26

# ===== Add LVM disk =====
qm importdisk $VMID $IMG_NAME $DISK_STORAGE
qm set $VMID \
  --scsihw virtio-scsi-pci \
  --scsi0 ${DISK_STORAGE}:"vm-$VMID-disk-0"

# ===== Boot order and console =====
qm set $VMID \
  --ide2 $DISK_STORAGE:cloudinit \
  --boot c \
  --bootdisk scsi0 \

# ===== Enable QEMU Guest Agent =====
qm set $VMID --agent enabled=1

# ===== Set autostart =====
qm set $VMID --onboot 1

# ===== Cloud-init =====
  --ipconfig0 ip=$IP_ADDR
  --ciuser=ubuntu \
  --sshkey ~/.ssh/id_rsa.pub \
  --cipassword 'Password1!' \
  --searchdomain cloud.local \
  --nameserver $DNS_SERVER \
  --ciupgrade 1

# ===== Start VM =====
#echo "Starting VM $VMID ($VM_NAME)..."
#qm start $VMID

#echo "VM $VMID ($VM_NAME) started successfully!"

echo "VM $VMID ($VM_NAME) created successfully!"
echo "Start it with: qm start $VMID"
