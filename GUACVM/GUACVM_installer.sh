#!/bin/bash

# ===== CONFIG =====
START_VMID=100
VM_NAME="GUACVM"
ISO_NAME="ubuntu-24.04.3-live-server-amd64.iso"
ISO_URL="https://releases.ubuntu.com/24.04/${ISO_NAME}"
ISO_STORAGE="local"
DISK_STORAGE="local-lvm"
MEMORY=4096
CORES=4
DISK_SIZE=32G
BRIDGE="vmbr0"
# ==================

set -e

# Find next available VMID
VMID=$START_VMID
while qm status $VMID &>/dev/null; do
    VMID=$((VMID + 1))
done

echo "Selected VMID: $VMID"

# Download ISO if missing
ISO_PATH="/var/lib/vz/template/iso/${ISO_NAME}"
if [ ! -f "$ISO_PATH" ]; then
    echo "Downloading Ubuntu 24.04.3 ISO..."
    wget -O "$ISO_PATH" "$ISO_URL"
else
    echo "ISO already exists."
fi

# Create VM
qm create $VMID \
  --name "${VM_NAME}-${VMID}" \
  --memory $MEMORY \
  --cores $CORES \
  --cpu host \
  --net0 virtio,bridge=$BRIDGE \
  --ostype l26

# Disk
qm set $VMID \
  --scsihw virtio-scsi-pci \
  --scsi0 ${DISK_STORAGE}:${DISK_SIZE}

# ISO
qm set $VMID \
  --cdrom ${ISO_STORAGE}:iso/${ISO_NAME}

# Boot + console
qm set $VMID \
  --boot order=scsi0,ide2 \
  --vga serial0 \
  --serial0 socket

# Guest agent
qm set $VMID --agent enabled=1

echo "VM $VMID created successfully"
echo "Start with: qm start $VMID"
