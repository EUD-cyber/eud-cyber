#!/bin/bash
set -e

LAB="$1"

if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  exit 1
fi

LOGFILE="$(pwd)/LOGS/VULNSRV01_lab${LAB}.log"

# Create log file and ensure permissions
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Redirect all output (stdout + stderr) to log AND console
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== VULNSRV01 installation started at $(date) ====="

# ===== CONFIG =====
START_VMID=$((LAB * 100))
BASE_NAME="lab${LAB}-VULN-SRV01"
#IMG_URL="https://cloud-images.ubuntu.com/noble/20251213/noble-server-cloudimg-amd64.img"
IMG_URL="https://cloud-images.ubuntu.com/noble/20260217/noble-server-cloudimg-amd64.img"
IMG_NAME="noble-server-cloudimg-amd64.img"
IMG_PATH="$(pwd)/$IMG_NAME"
ISO_STORAGE="local"
DISK_STORAGE="local-lvm"
MEMORY=4096       # in MB
CORES=4
DISK_SIZE="32G"    # the number is in GB
BRIDGE="lab${LAB}_lan1"
BRIDGE1="lab${LAB}_oobm"
IP_ADDR="ip=192.168.1.20/24"
DNS_SERVER="192.168.1.1"
IP_GW="gw=192.168.1.1"
OOBM_IP="ip=172.20.0.10/24"
SNIPPET_DIR="/var/lib/vz/snippets"
SRC_USERDATA="$(pwd)/VULNSRV01/VULNSRV01_userdata.yaml"     # source file
DST_USERDATA="VULNSRV01_userdata_lab${LAB}.yaml"            # destination filename

DST_PATH="${SNIPPET_DIR}/${DST_USERDATA}"

echo "Checking Cloud-Init user-data snippet..."

# Check if snippet already exists
if [[ -f "$DST_PATH" ]]; then
  echo "User-data already exists: $DST_PATH"
else
  echo "User-data not found. Copying..."
  cp "$SRC_USERDATA" "$DST_PATH"
  chmod 644 "$DST_PATH"
  echo "User-data copied to $DST_PATH"
fi
echo "Done."

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
  --net1 virtio,bridge=$BRIDGE1 \
  --ostype l26

# ===== Add LVM disk =====
qm importdisk $VMID $IMG_NAME $DISK_STORAGE
qm set $VMID \
  --scsihw virtio-scsi-pci \
  --scsi0 ${DISK_STORAGE}:"vm-$VMID-disk-0"

qm disk resize $VMID scsi0 +$DISK_SIZE

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
qm set $VMID --ipconfig0 $IP_ADDR,$IP_GW \
  --ipconfig1 $OOBM_IP \
  --searchdomain cloud.local \
  --nameserver $DNS_SERVER \
  --ciupgrade \
  --cicustom "user=local:snippets/${DST_USERDATA}"

#Creating first snapshot of the VM 
qm snapshot $VMID First_snapshot --description "Clean baseline snapshot for lab reset"

# ===== Start VM =====
echo "Starting VM $VMID ($VM_NAME)..."
qm start $VMID

echo "VM $VMID ($VM_NAME) started successfully!"
