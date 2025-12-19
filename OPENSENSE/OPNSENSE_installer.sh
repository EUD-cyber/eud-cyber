#!/bin/bash
set -e

### ===== VARIABLES =====
START_VMID=100
BASE_NAME="opnsense"
RAM=2048
CORES=2
DISK_SIZE=20G

# Proxmox storage
DISK_STORAGE="local-lvm"
ISO_STORAGE="local"

# Bridges
WAN_BRIDGE="vmbr0"
LAN_BRIDGE="lan1"

#install bzip2 for unzip opensense iso
apt install -y wget bzip2

# OPNsense
OPN_VERSION="24.1"
ISO_NAME="OPNsense-${OPN_VERSION}-dvd-amd64.iso"
ISO_PATH="/var/lib/vz/template/iso/${ISO_NAME}"

CONFIG_SRC="/root/opnsense/config.xml"
HOOK_PATH="/var/lib/vz/snippets/opnsense-hook.sh"

### ===== CHECKS =====
if [[ ! -f "$CONFIG_SRC" ]]; then
  echo "ERROR: config.xml not found at $CONFIG_SRC"
  exit 1
fi

### ===== DOWNLOAD ISO =====
if [[ ! -f "$ISO_PATH" ]]; then
  echo "Downloading OPNsense ISO..."
  wget -O "$ISO_PATH" \
    https://mirror.opnsense.org/releases/${OPN_VERSION}/${ISO_NAME}
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
  --name $VM_NAME \
  --memory $RAM \
  --cores $CORES \
  --cpu host \
  --ostype l26 \
  --scsihw virtio-scsi-pci \
  --net0 virtio,bridge=$WAN_BRIDGE \
  --net1 virtio,bridge=$LAN_BRIDGE

### ===== DISKS =====
qm set $VMID \
  --scsi0 $DISK_STORAGE:$DISK_SIZE \
  --scsi1 $DISK_STORAGE:1 \
  --cdrom $ISO_STORAGE:iso/$ISO_NAME \
  --boot order=scsi0

qm set $VMID --serial0 socket --vga serial0

### ===== HOOK SCRIPT (inject config.xml) =====
cat > "$HOOK_PATH" <<EOF
#!/bin/bash
VMID="\$1"
PHASE="\$2"

if [ "\$PHASE" = "pre-start" ]; then
  qm mount \$VMID --disk scsi1 --mountpoint /mnt
  mkdir -p /mnt/conf
  cp $CONFIG_SRC /mnt/conf/config.xml
  qm unmount \$VMID
fi
EOF

chmod +x "$HOOK_PATH"

qm set $VMID --hookscript local:snippets/opnsense-hook.sh

### ===== START VM =====
qm start $VMID

echo "✔ OPNsense VM $VMID deployed and booting"
