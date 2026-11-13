#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

LAB="$1"

if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  exit 1
fi

# Reserved deployment settings; not applied to cloud-init or services yet.
# Keep existing direct calls compatible. Lab deployment will select agent later.
MRNOBODY_ROLE="${MRNOBODY_ROLE:-standalone}"
MRNOBODY_MASTER_URL="${MRNOBODY_MASTER_URL:-}"

case "$MRNOBODY_ROLE" in
  standalone|agent) ;;
  master)
    echo "Master is reserved for the future Single VM installer." >&2
    exit 1
    ;;
  *)
    echo "MRNOBODY_ROLE must be standalone or agent." >&2
    exit 1
    ;;
esac

# An empty URL is valid: existing labs must not require an available Master.
# Accept an HTTPS DNS/IPv4 authority with an optional port and path.
if [[ -n "$MRNOBODY_MASTER_URL" ]]; then
  master_url_pattern='^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:([0-9]{1,5}))?(/[A-Za-z0-9._~%/+-]*)?$'
  if ! [[ "$MRNOBODY_MASTER_URL" =~ $master_url_pattern ]]; then
    echo "MRNOBODY_MASTER_URL must be an HTTPS URL without credentials, query or fragment." >&2
    exit 1
  fi
  master_port="${BASH_REMATCH[3]:-443}"
  if (( 10#$master_port < 1 || 10#$master_port > 65535 )); then
    echo "MRNOBODY_MASTER_URL port must be between 1 and 65535." >&2
    exit 1
  fi
fi

LOGFILE="$(pwd)/LOGS/mrnobody${LAB}.log"

# Create log file and ensure permissions
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Redirect all output (stdout + stderr) to log AND console
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== mynobody installation started at $(date) ====="

# ===== CONFIG =====
START_VMID=$((LAB * 1000))
BASE_NAME="lab${LAB}-MrNobody"
IMG_URL="${LINUX_IMG:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
IMG_NAME="noble-server-cloudimg-amd64.img"
IMG_PATH="$(pwd)/$IMG_NAME"
ISO_STORAGE="${LOCAL:-local}"
DISK_STORAGE="${LVM:-local-lvm}"
MEMORY="${MRNOBODY_MEM:-4096}"       # in MB
CORES="${MRNOBODY_CPU:-4}"
DISK_SIZE="${MRNOBODY_HDD:-32G}"    # the number is in GB
BRIDGE="lab${LAB}_lan1"
BRIDGE2="lab${LAB}_lan2"
BRIDGE1="lab${LAB}_oobm"
IP_ADDR="ip=192.168.1.254/24"
IP_ADDR2="ip=192.168.2.254/24"
DNS_SERVER="192.168.1.1"
IP_GW="gw=192.168.1.1"
OOBM_IP="ip=172.20.0.254/24"
SNIPPET_DIR="/var/lib/vz/snippets"
SRC_USERDATA="$(pwd)/MRNOBODY/mrnobody_userdata.yaml"     # source file
DST_USERDATA="mrnobody_userdata_lab${LAB}.yaml"            # destination filename

DST_PATH="${SNIPPET_DIR}/${DST_USERDATA}"

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
  --net2 virtio,bridge=$BRIDGE2 \
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
  --ipconfig2 $IP_ADDR2 \
  --searchdomain cloud.local \
  --nameserver $DNS_SERVER \
  --ciupgrade \
  --cicustom "user=$ISO_STORAGE:snippets/${DST_USERDATA}"

# ===== Start VM =====
echo "Starting VM $VMID ($VM_NAME)..."
qm start $VMID

echo "VM $VMID ($VM_NAME) started successfully!"

echo "Waiting for VM to power off..."

while true; do
  STATUS=$(qm status "$VMID" | awk '{print $2}')

  if [[ "$STATUS" == "stopped" ]]; then
    echo "VM is powered off."
    break
  fi

  sleep 5
done

echo "Creating snapshot..."
qm snapshot "$VMID" First_snapshot --description "Clean baseline snapshot for lab reset"

echo "Snapshot created successfully."

echo "Starting VM again..."
qm start "$VMID"

echo "VM started."
