#!/bin/bash
set -e

LOGFILE="$(pwd)/LOGS/WIN2025.log"

# Create log file and ensure permissions
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Redirect all output (stdout + stderr) to log AND console
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== WIN2025 installation started at $(date) ====="


START_VMID="100"
BASE_NAME="WIN2025"
ISO_STORAGE="local"
DISK_STORAGE="local-lvm"
IMG_URL="https://go.microsoft.com/fwlink/?linkid=2345730&clcid=0x409&culture=en-us&country=us"
IMG_NAME="en-us_windows_server_2025_x64_dvd_b7ec10f3.iso"
IMG_PATH="$(pwd)IMAGES/$IMG_NAME"
VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.285-1/virtio-win-0.1.285.iso"
VIRTIO_NAME="virtio-win.iso"
VIRTIO_PATH="$(pwd)/IMAGES/$VIRTIO_NAME"
MEMORY=8192       # in MB
CORES=4
DISK_SIZE="40"
BRIDGE="lan2"
BRIDGE1="oobm"
ISO_DIR="/var/lib/vz/template/iso/"
AUTO_FOLDER="$(pwd)/WIN2025/Autounattend"
AUTO_PATH="$(pwd)/WIN2025/Autounattend/Autounattend.xml"
AUTOISO_PATH="/var/lib/vz/template/iso/Autounattend.iso"
AUTOISO_NAME="Autounattend.iso"
DST_WIN2025_PATH="$ISO_DIR/$IMG_NAME"
DST_VIRTIO_PATH="$ISO_DIR/$VIRTIO_NAME"


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

# ===== Download VIRTIO if missing =====
if [ ! -f "$VIRTIO_PATH" ]; then
    echo "Downloading $VIRTIO_NAME IMG..."
    wget --show-progress -O "$VIRTIO_PATH" "$VIRTIO_URL"
else
    echo "IMG already exists: $VIRTIO_PATH"
fi

# ===== Download IMG if missing =====
if [ ! -f "$IMG_PATH" ]; then
    echo "Downloading $IMG_NAME IMG..."
    wget --show-progress -O "$IMG_PATH" "$IMG_URL"
else
    echo "IMG already exists: $IMG_PATH"
fi

# Check if WIN2025 ISO exits in iso folder
if [[ -f "$DST_WIN2025_PATH" ]]; then
  echo "WIN2025 ISO already exists: $DST_WIN2025_PATH"
else
  echo "WIN2025 ISO not found. Copying..."
  cp "$IMG_PATH" "$DST_WIN2025_PATH"
  echo "VIRTIO ISO copied to $DST_WIN2025_PATH"

fi
  
# Check if VIRTIO ISO exits in iso folder
if [[ -f "$DST_VIRTIO_PATH" ]]; then
  echo "VIRTIO ISO already exists: $DST_VIRTIO_PATH"
else
  echo "VIRTIO ISO not found. Copying..."
  cp "$VIRTIO_PATH" "$DST_VIRTIO_PATH"
  echo "VIRTIO ISO copied to $DST_VIRTIO_PATH"

fi

# Check if Autounattend.iso exits
if [[ -f "$AUTOISO_PATH" ]]; then
  echo "Autounattend.iso exits: $AUTOISO_PATH"
else
  echo "ISO file not found. Zipping " $AUTO_PATH
  genisoimage -o $AUTOISO_PATH -J -R $AUTO_FOLDER
  echo "Autounattend.iso is created $AUTOZIP_PATH"

fi

echo "Done."

qm create $VMID \
  --name $VM_NAME \
  --memory $MEMORY \
  --cores $CORES \
  --cpu host \
  --net0 virtio,bridge=$BRIDGE \
  --net1 virtio,bridge=$BRIDGE1 \
  --scsihw virtio-scsi-pci \
  --ostype win11

qm set $VMID --ide1 $ISO_STORAGE:iso/$IMG_NAME,media=cdrom
qm set $VMID --ide2 $ISO_STORAGE:iso/$VIRTIO_NAME,media=cdrom
qm set $VMID --ide3 $ISO_STORAGE:iso/$AUTOISO_NAME,media=cdrom
qm set $VMID --scsi0 $DISK_STORAGE:$DISK_SIZE

qm set $VMID --boot order=scsi0 \
   --machine q35 \
   --bios ovmf \
   --efidisk0 $DISK_STORAGE:0,pre-enrolled-keys=1 \
   --tpmstate0 $DISK_STORAGE:0,version=v2.0 \
   --tablet 0
qm enroll-efi-keys $VMID
qm start $VMID
