#!/bin/bash
set -e

# ===== CONFIG =====
START_VMID=100
BASE_NAME="GUACVM"
#ISO_NAME="ubuntu-24.04.3-live-server-amd64.iso"
#ISO_URL="https://releases.ubuntu.com/24.04/${ISO_NAME}"
IMG_URL="https://cloud-images.ubuntu.com/noble/20251213/noble-server-cloudimg-amd64.img"
IMG_NAME="noble-server-cloudimg-amd64.img"
IMG_PATH="$(pwd)"
ISO_STORAGE="local"
DISK_STORAGE="local-lvm"
MEMORY=4096       # in MB
CORES=4
DISK_SIZE="32"    # the number is in GB
BRIDGE="vmbr0"
CLOUDINIT_FILE="$(pwd)/GUACVM/GUACVM-cloud-init"
# ==================

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

# ===== Download ISO if missing =====
#ISO_PATH="/var/lib/vz/template/iso/${ISO_NAME}"
#if [ ! -f "$ISO_PATH" ]; then
#    echo "Downloading Ubuntu 24.04.3 ISO..."
#    wget --show-progress -O "$ISO_PATH" "$ISO_URL"
#else
#    echo "ISO already exists: $ISO_PATH"
#fi

# ===== Download IMG if missing =====
if [ ! -f "$IMG_PATH" ]; then
    echo "Downloading $IMG_NAME IMG..."
    wget --show-progress -O "IMG_PATH" "IMG_URL"
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


# ===== Attach ISO =====
qm set $VMID \
  --cdrom ${ISO_STORAGE}:iso/${ISO_NAME}

# ===== Boot order and console =====
qm set $VMID \
  --boot "order=ide2;scsi0" \
  --vga serial0 \
  --serial0 socket

# ===== Enable QEMU Guest Agent =====
qm set $VMID --agent enabled=1

# ===== Add external Cloud-Init disk =====
qm import $VMID $CLOUDINIT_FILE $DISK_STORAGE
qm set $VMID --ide0 $DISK_STORAGE:cloudinit

# ===== Set autostart =====
qm set $VMID --onboot 1

# ===== Start VM =====
echo "Starting VM $VMID ($VM_NAME)..."
qm start $VMID

echo "VM $VMID ($VM_NAME) started successfully!"
echo "Ubuntu Server autoinstall via external Cloud-Init file is in progress."

echo "VM $VMID ($VM_NAME) created successfully!"
echo "Start it with: qm start $VMID"
