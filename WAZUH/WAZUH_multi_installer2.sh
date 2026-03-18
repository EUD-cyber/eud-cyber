#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

LAB="$1"

if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  exit 1
fi

# -----------------------------
# CONFIG
# -----------------------------
START_VMID=$((LAB * 1000))
BASE_NAME="lab${LAB}-WAZUH"
IMG_URL="${WAZUH_IMG:-https://packages.wazuh.com/4.x/vm/wazuh-4.14.1.ova}"
IMG_NAME="wazuh.ova"
IMG_PATH="$(pwd)/WAZUH/$IMG_NAME"
STORAGE="${LOCAL:-local}"
DISK_STORAGE="${LVM:-local-lvm}"
BRIDGE1="lab${LAB}_lan2"
BRIDGE2="lab${LAB}_oobm"
CORES=4
MEMORY=16384
DISK_SIZE=80G
IP_ADDR="ip=192.168.2.20/24"
DNS_SERVER="192.168.2.1"
OOBM_IP="ip=172.20.0.20/24"
IP_GW="gw=192.168.2.1"
WORKDIR="$(pwd)/WAZUH/"
SNIPPET_DIR="/var/lib/vz/snippets"
SRC_USERDATA="$(pwd)/WAZUH/WAZUH_userdata.yaml"     # source file
DST_USERDATA="WAZUH_userdata_lab${LAB}.yaml"            # destination filename
# -----------------------------

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
    wget -q --show-progress -O "$IMG_PATH" "$IMG_URL"
else
    echo "IMG already exists: $IMG_PATH"
fi

echo "➡ Extracting OVA..."
tar -xf "$IMG_PATH" -C $WORKDIR

VMDK_FILE=$(ls "$WORKDIR"*.vmdk | head -n 1)

if [[ ! -f "$VMDK_FILE" ]]; then
  echo "❌ vmdk not found — aborting"
  exit 1
fi

echo "➡ Updating VM settings..."
qm create "$VMID" \
  --name "$VM_NAME" \
  --cores "$CORES" \
  --memory "$MEMORY" \
  --cpu host \
  --machine q35 \
  --scsihw virtio-scsi-pci \
  --net0 virtio,bridge="$BRIDGE1" \
  --net1 virtio,bridge="$BRIDGE2"

qm importdisk "$VMID" "$VMDK_FILE" "$DISK_STORAGE" --format raw

qm set "$VMID" --scsi0 "$DISK_STORAGE:vm-$VMID-disk-0"
qm disk resize $VMID scsi0 +$DISK_SIZE
echo "➡ Adding cloud-init drive..."
qm set "$VMID" --ide2 "$DISK_STORAGE":cloudinit

echo "➡ Setting boot options..."
qm set "$VMID" --boot c --bootdisk scsi0

qm set $VMID --ipconfig0 $IP_ADDR,$IP_GW \
  --ipconfig1 $OOBM_IP \
  --searchdomain cloud.local \
  --nameserver $DNS_SERVER \
  --ciupgrade \

echo "➡ Attaching custom cloud-init config..."
qm set "$VMID" --cicustom "user=local:snippets/${DST_USERDATA}"

#Creating first snapshot of the VM 
qm snapshot $VMID First_snapshot --description "Clean baseline snapshot for lab reset"

echo "➡ Done — starting VM..."
qm start "$VMID"
