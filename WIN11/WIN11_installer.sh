#!/bin/bash
set -e

VMID=130
VMNAME="win11"
STORAGE="local-lvm"
BRIDGE="lan1"
ISO_DIR="/var/lib/vz/template/iso"
WIN_ISO="$ISO_DIR/Win11.iso"
VIRTIO_ISO="$ISO_DIR/virtio-win.iso"

echo "[+] Downloading Windows 11 ISO"
wget -O "$WIN_ISO" \
https://software-download.microsoft.com/download/pr/Windows11_23H2_English_x64.iso

echo "[+] Downloading VirtIO drivers"
wget -O "$VIRTIO_ISO" \
https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso

echo "[+] Creating VM $VMID"

qm create $VMID \
  --name "$VMNAME" \
  --memory 8192 \
  --cores 4 \
  --cpu host \
  --machine q35 \
  --bios ovmf \
  --efidisk0 $STORAGE:1,efitype=4m,pre-enrolled-keys=1 \
  --tpmstate0 $STORAGE:1,version=v2.0 \
  --scsihw virtio-scsi-pci \
  --scsi0 $STORAGE:64 \
  --net0 virtio,bridge=$BRIDGE \
  --vga std \
  --ostype win11

qm set $VMID --ide2 local:iso/Win11.iso,media=cdrom
qm set $VMID --ide3 local:iso/virtio-win.iso,media=cdrom

# Attach Autounattend.xml as floppy
qm set $VMID --floppy0 local:snippets/autounattend.xml

qm set $VMID --boot order=scsi0

echo "✅ VM created. Starting installation…"
qm start $VMID
