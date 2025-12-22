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
SNIPPET_DIR="/var/lib/vz/snippets"
SRC_USERDATA="$(pwd)/GUACVM/GUAC_userdata.yaml"     # source file
DST_USERDATA="GUAC_userdata.yaml"            # destination filename
# ==================

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

# Ask user for network type
echo "Select network configuration:"
echo "1) DHCP"
echo "2) Static"
read -p "Enter choice [1-2]: " choice

if [ "$choice" = "1" ]; then
    IP_ADDR="ip=dhcp"
    DNS_SERVER=""

elif [ "$choice" = "2" ]; then

validate_ip_cidr() {
  ipcalc -cs "$1" >/dev/null 2>&1
}
validate_ip_only() {
  ipcalc -c "$ip" >/dev/null 2>&1
}
while true; do
  read -rp "Enter IP address with CIDR (e.g. 192.168.1.10/24): " STATIC_IP
  if validate_ip_cidr "$STATIC_IP"; then
    echo "✔ Valid IP/CIDR: $STATIC_IP"
    break
  else
    echo "✖ Invalid IP/CIDR. Please try again."
  fi
done
while true; do
  read -rp "Enter gateway (e.g. 192.168.1.1): " GATEWAY
  if validate_ip_only "$GATEWAY"; then
    echo "✔ Valid IP/CIDR: $GATEWAY"
    break
  else
    echo "✖ Invalid IP. Please try again."
  fi
done


#    read -p "Enter static IP (e.g., 192.168.1.100/24): " STATIC_IP
#    read -p "Enter gateway (e.g., 192.168.1.1): " GATEWAY
  read -p "Enter DNS servers (space separated, e.g., 8.8.8.8 1.1.1.1): " DNS

    IP_ADDR="ip=${STATIC_IP},gw=${GATEWAY}"
    DNS_SERVER="$DNS"

else
    echo "Invalid choice. Exiting."
    exit 1
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
qm set $VMID --sshkeys ~/.ssh/id_rsa.pub \
  --ipconfig0 $IP_ADDR \
  --ciuser=ubuntu \
  --cipassword 'Password1!' \
  --searchdomain cloud.local \
  --nameserver $DNS_SERVER \
  --ciupgrade 1
  --cicustom "user=local:snippets/GUAC_userdata.yaml"


# ===== Start VM =====
echo "Starting VM $VMID ($VM_NAME)..."
qm start $VMID

echo "VM $VMID ($VM_NAME) started successfully!"

