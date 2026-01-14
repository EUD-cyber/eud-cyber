#!/bin/bash
set -e

LOGFILE="$(pwd)/LOGS/OPNSENSE.log"

# Create log file and ensure permissions
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Redirect all output (stdout + stderr) to log AND console
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== OPNSENSE installation started at $(date) ====="

### ===== VARIABLES =====
START_VMID=100
BASE_NAME="opnsense"
RAM=4096
CORES=2
DISK_SIZE=30G

# Proxmox storage
DISK_STORAGE="local-lvm"
ISO_STORAGE="local"

# Bridges
WAN_BRIDGE="vmbr0"
LAN_BRIDGE="lan1"
LAN_BRIDGE1="lan2"
OOBM="oobm"

#OPN_VERSION="24.1"
OPN_VERSION="25.7"

IMG_BASE="OPNsense-${OPN_VERSION}-nano-amd64.img"
IMG_BZ2="${IMG_BASE}.bz2"

IMG_DIR="$(pwd)/OPNSENSE"
IMG_PATH="${IMG_DIR}/${IMG_BASE}"
IMG_BZ2_PATH="${IMG_DIR}/${IMG_BZ2}"

ISO_PATH="/var/lib/vz/template/iso/opnsense-config.iso"

GENERATESH="$(pwd)/OPNSENSE/generate_config.sh"
CONFIG_ISO="$(pwd)/OPNSENSE/iso"
CONFIG_SRC="$(pwd)/OPNSENSE/iso/conf/config.xml"


## ===== CHECKS =====
if [[ ! -f "$CONFIG_SRC" ]]; then
#  echo "ERROR: config.xml not found at $CONFIG_SRC"
  echo "generating config.xml"
  bash $GENERATESH
fi

#mkdir -p "$IMG_DIR"

### ===== DOWNLOAD IMG.BZ2 =====
if [[ ! -f "$IMG_PATH" ]]; then
  if [[ ! -f "$IMG_BZ2_PATH" ]]; then
    echo "Downloading OPNsense nano image..."
    wget -O "$IMG_BZ2_PATH" \
      https://pkg.opnsense.org/releases/${OPN_VERSION}/${IMG_BZ2}
  fi

  echo "Unpacking image..."
  bunzip2 -fk "$IMG_BZ2_PATH"
fi

## ===== CHECK IF ISO EXITS =====
if [[ ! -f "$ISO_PATH" ]]; then
#  echo opnsense-config.iso not found at $ISO_PATH"
  echo "generating opnsense-config.iso"
  cd $CONFIG_ISO
  genisoimage -o $ISO_PATH -J -r -V OPNCONF .
fi


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


### ===== CREATE VM =====
qm create $VMID \
  --name "$VM_NAME" \
  --memory $RAM \
  --cores $CORES \
  --cpu host \
  --bios seabios \
  --ostype l26 \
  --scsihw virtio-scsi-pci \
  --net0 virtio,bridge=$LAN_BRIDGE \
  --net1 virtio,bridge=$WAN_BRIDGE \
  --net2 virtio,bridge=$LAN_BRIDGE1 \
  --net3 virtio,bridge=$OOBM \
  --boot order=scsi0 \
  --serial0 socket \
  --vga std

### ===== IMPORT DISK =====
qm importdisk $VMID "$IMG_PATH" $DISK_STORAGE

# Attach imported disk as scsi0
qm set $VMID --scsi0 $DISK_STORAGE:vm-$VMID-disk-0

qm disk resize $VMID scsi0 +$DISK_SIZE


# Attach cdrom to vm
qm set $VMID --ide2 local:iso/opnsense-config.iso,media=cdrom

### ===== START VM =====
qm start $VMID

echo "Waiting for OPNsense bootstrap prompt..."

expect <<EOF
set timeout -1

# Attach to VM console
spawn qm terminal $VMID

# WAIT for text, then press ENTER
expect {
    "Press any key to start" {
        send "\r"
        exp_continue
    }

    "Select device to import from (e.g. ada0) or leave blank to exit" {
        send "\cd0\r"
        exit
    }
    eof
}
EOF

echo "✔ OPNsense VM $VMID deployed"
