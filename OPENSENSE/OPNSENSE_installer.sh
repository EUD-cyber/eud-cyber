#!/bin/bash
set -e

### ===== VARIABLES =====
START_VMID=100
BASE_NAME="opnsense"
RAM=2048
CORES=2
DISK_SIZE=20

# Proxmox storage
DISK_STORAGE="local-lvm"
ISO_STORAGE="local"

# Bridges
WAN_BRIDGE="vmbr0"
LAN_BRIDGE="lan1"

#install bzip2 for unzip opensense iso
apt install -y wget bzip2

OPN_VERSION="24.1"
IMG_BASE="OPNsense-${OPN_VERSION}-nano-amd64.img"
IMG_BZ2="${IMG_BASE}.bz2"

IMG_DIR="/var/lib/vz/template"
IMG_PATH="${IMG_DIR}/${IMG_BASE}"
IMG_BZ2_PATH="${IMG_DIR}/${IMG_BZ2}"

CONFIG_SRC="/root/opnsense/config.xml"
HOOK="/var/lib/vz/snippets/opnsense-hook.sh"

### ===== CHECKS =====
if [[ ! -f "$CONFIG_SRC" ]]; then
  echo "ERROR: config.xml not found at $CONFIG_SRC"
  exit 1
fi

mkdir -p "$IMG_DIR"

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
  --net0 virtio,bridge=$WAN_BRIDGE \
  --net1 virtio,bridge=$LAN_BRIDGE \
  --boot order=scsi0 \
  --vga std

### ===== IMPORT DISK =====
qm importdisk $VMID "$IMG_PATH" $STORAGE --format raw

# Attach imported disk as scsi0
qm set $VMID --scsi0 $STORAGE:vm-$VMID-disk-0

### ===== CONFIG DISK FOR config.xml =====
qm set $VMID --scsi1 $STORAGE:1

### ===== HOOK SCRIPT (inject config.xml) =====
cat > "$HOOK_PATH" <<EOF
#!/bin/bash
VMID="$1"
PHASE="$2"

CONFIG_SRC="/root/opnsense/config.xml"
MOUNTPOINT="/mnt/opnsense-config"
DISK="scsi1"

if [ "$PHASE" = "pre-start" ]; then
  echo "[HOOK] Injecting OPNsense config.xml"

  mkdir -p "$MOUNTPOINT"

  qm disk mount "$VMID" "$DISK" "$MOUNTPOINT"

  mkdir -p "$MOUNTPOINT/conf"
  cp "$CONFIG_SRC" "$MOUNTPOINT/conf/config.xml"

  qm disk unmount "$VMID" "$DISK"
fi

EOF

chmod +x "$HOOK_PATH"

qm set $VMID --hookscript local:snippets/opnsense-hook.sh

### ===== START VM =====
qm start $VMID

echo "✔ OPNsense VM $VMID deployed and booting"
