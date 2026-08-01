#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
# Cyberlab Image Server installer
#
# Creates a standalone Ubuntu Image Server VM with one network interface:
#
#   net0 -> vmbr0
#
# Usage:
#   ./IMAGESRV/install.sh <lab-number>
#
# Example:
#   ./IMAGESRV/install.sh 1
###############################################################################

LAB="${1:-}"

if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  echo "Example: $0 1"
  exit 1
fi

PROJECT_DIR="$(pwd)"
STATE_FILE="${PROJECT_DIR}/IMAGESRV/STATE/lab${LAB}.env"
LOG_DIR="${PROJECT_DIR}/LOGS"
LOGFILE="${LOG_DIR}/IMAGESRV${LAB}.log"

###############################################################################
# Helper functions
###############################################################################

log() {
  printf '[+] %s\n' "$*"
}

warning() {
  printf '[WARNING] %s\n' "$*" >&2
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

bridge_exists() {
  ip link show "$1" >/dev/null 2>&1
}

storage_exists() {
  pvesm status 2>/dev/null |
    awk 'NR > 1 {print $1}' |
    grep -Fxq "$1"
}

is_valid_ipv4() {
  local ip="$1"
  local octet
  local -a octets

  IFS='.' read -r -a octets <<< "$ip"

  [[ ${#octets[@]} -eq 4 ]] || return 1

  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( octet >= 0 && octet <= 255 )) || return 1
  done
}

is_valid_cidr() {
  local value="$1"
  local ip
  local prefix

  [[ "$value" == */* ]] || return 1

  ip="${value%/*}"
  prefix="${value#*/}"

  is_valid_ipv4 "$ip" || return 1
  [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
  (( prefix >= 0 && prefix <= 32 ))
}

wait_for_vm_shutdown() {
  local vmid="$1"
  local timeout_seconds="${2:-3600}"
  local waited=0
  local status

  log "Waiting for VM ${vmid} to power off after cloud-init..."

  while (( waited < timeout_seconds )); do
    status="$(
      qm status "$vmid" 2>/dev/null |
        awk '{print $2}'
    )"

    if [[ "$status" == "stopped" ]]; then
      log "VM ${vmid} is powered off."
      return 0
    fi

    sleep 5
    waited=$((waited + 5))

    if (( waited % 60 == 0 )); then
      log "Still waiting: ${waited}/${timeout_seconds} seconds"
    fi
  done

  return 1
}

cleanup_failed_vm() {
  local vmid="${1:-}"

  if [[ -n "$vmid" ]] && qm status "$vmid" >/dev/null 2>&1; then
    warning "Installation failed after VM ${vmid} was created."
    warning "The VM has not been removed automatically."
    warning "Remove it manually with:"
    warning "qm stop ${vmid} --skiplock 1 || true"
    warning "qm destroy ${vmid} --purge 1"
  fi
}

###############################################################################
# Validate Proxmox host
###############################################################################

[[ "$EUID" -eq 0 ]] ||
  die "Run this script as root on the Proxmox host."

command_exists qm ||
  die "The qm command is missing. Run this on a Proxmox host."

command_exists pvesm ||
  die "The pvesm command is missing."

command_exists wget ||
  die "wget is required."

[[ -f "$STATE_FILE" ]] ||
  die "Missing Image Server state file: ${STATE_FILE}"

# Load variables such as LOCAL, LVM, BRIDGE and LINUX_IMG.
# shellcheck disable=SC1090
source "$STATE_FILE"

mkdir -p "$LOG_DIR"
touch "$LOGFILE"
chmod 600 "$LOGFILE"

exec > >(tee -a "$LOGFILE") 2>&1

echo
echo "================================================================="
echo " Cyberlab standalone Image Server installation"
echo " Lab number: ${LAB}"
echo " Started: $(date)"
echo "================================================================="
echo

###############################################################################
# Configuration
###############################################################################

START_VMID=$((LAB * 1000))
BASE_NAME="lab${LAB}-imagesrv"

IMG_URL="${LINUX_IMG:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
IMG_NAME="noble-server-cloudimg-amd64.img"
IMG_PATH="${PROJECT_DIR}/${IMG_NAME}"

ISO_STORAGE="${LOCAL:-local}"
DISK_STORAGE="${LVM:-local-lvm}"

MEMORY=4096
CORES=2

# Final disk size.
# The Ubuntu cloud image is expanded to this exact size.
DISK_SIZE="100G"

# The Image Server only has one NIC.
EXTERNAL_BRIDGE="${BRIDGE:-vmbr0}"

SNIPPET_DIR="/var/lib/vz/snippets"

SRC_USERDATA="${PROJECT_DIR}/IMAGESRV/IMAGESRV_userdata.yaml"
DST_USERDATA="IMAGESRV_userdata_lab${LAB}.yaml"
DST_PATH="${SNIPPET_DIR}/${DST_USERDATA}"

VMID=""

trap 'cleanup_failed_vm "$VMID"' ERR

###############################################################################
# Validate configuration
###############################################################################

log "Validating Proxmox configuration..."

bridge_exists "$EXTERNAL_BRIDGE" ||
  die "Bridge does not exist: ${EXTERNAL_BRIDGE}"

storage_exists "$ISO_STORAGE" ||
  die "Proxmox snippet storage does not exist: ${ISO_STORAGE}"

storage_exists "$DISK_STORAGE" ||
  die "Proxmox disk storage does not exist: ${DISK_STORAGE}"

[[ -f "$SRC_USERDATA" ]] ||
  die "Cloud-init file does not exist: ${SRC_USERDATA}"

mkdir -p "$SNIPPET_DIR"

###############################################################################
# Network configuration
###############################################################################

echo
echo "================================================================="
echo " Image Server network configuration"
echo "================================================================="
echo
echo "The VM will only have one network interface:"
echo
echo "  net0 -> ${EXTERNAL_BRIDGE}"
echo
echo "The IP address must be reachable from all Proxmox servers"
echo "that need to download images from the repository."
echo

read -r -p "Use DHCP on net0? [y/N]: " USE_DHCP
USE_DHCP="${USE_DHCP:-n}"

IMAGE_SERVER_DNS=""

if [[ "$USE_DHCP" =~ ^[Yy]$ ]]; then
  IMAGE_SERVER_IPCONFIG="ip=dhcp"

  while true; do
    read -r -p \
      "Optional DNS server (leave empty to use DHCP): " \
      IMAGE_SERVER_DNS

    if [[ -z "$IMAGE_SERVER_DNS" ]] ||
       is_valid_ipv4 "$IMAGE_SERVER_DNS"; then
      break
    fi

    echo "Invalid IPv4 DNS address."
  done
else
  while true; do
    read -r -p \
      "Image Server IP with CIDR [example 10.134.71.170/24]: " \
      IMAGE_SERVER_IP

    if is_valid_cidr "$IMAGE_SERVER_IP"; then
      break
    fi

    echo "Invalid value."
    echo "Enter an IPv4 address with CIDR, for example:"
    echo "10.134.71.170/24"
  done

  while true; do
    read -r -p \
      "Default gateway [example 10.134.71.1]: " \
      IMAGE_SERVER_GATEWAY

    if is_valid_ipv4 "$IMAGE_SERVER_GATEWAY"; then
      break
    fi

    echo "Invalid IPv4 gateway."
  done

  DEFAULT_DNS="${GUAC_DNS_SERVER:-1.1.1.1}"

  while true; do
    read -r -p \
      "DNS server [${DEFAULT_DNS}]: " \
      IMAGE_SERVER_DNS

    IMAGE_SERVER_DNS="${IMAGE_SERVER_DNS:-$DEFAULT_DNS}"

    if is_valid_ipv4 "$IMAGE_SERVER_DNS"; then
      break
    fi

    echo "Invalid IPv4 DNS server."
  done

  IMAGE_SERVER_IPCONFIG="ip=${IMAGE_SERVER_IP},gw=${IMAGE_SERVER_GATEWAY}"
fi

###############################################################################
# Show summary
###############################################################################

echo
echo "================================================================="
echo " Installation summary"
echo "================================================================="
echo
echo "Lab number:          ${LAB}"
echo "Base VM name:        ${BASE_NAME}"
echo "Starting VMID:       ${START_VMID}"
echo
echo "Network interfaces:  1"
echo "net0 bridge:         ${EXTERNAL_BRIDGE}"
echo "net0 configuration:  ${IMAGE_SERVER_IPCONFIG}"
echo "DNS server:          ${IMAGE_SERVER_DNS:-Provided through DHCP}"
echo
echo "Snippet storage:     ${ISO_STORAGE}"
echo "Disk storage:        ${DISK_STORAGE}"
echo "Memory:              ${MEMORY} MB"
echo "CPU cores:           ${CORES}"
echo "Disk size:           ${DISK_SIZE}"
echo "Ubuntu image:        ${IMG_URL}"
echo "Cloud-init file:     ${SRC_USERDATA}"
echo

read -r -p "Continue with this configuration? [Y/n]: " CONFIRM
CONFIRM="${CONFIRM:-y}"

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
  echo "Installation cancelled."
  exit 0
fi

###############################################################################
# Install cloud-init snippet
###############################################################################

log "Installing cloud-init user-data snippet..."

install \
  -m 0644 \
  "$SRC_USERDATA" \
  "$DST_PATH"

log "Cloud-init snippet installed: ${DST_PATH}"

###############################################################################
# Find next free VMID
###############################################################################

VMID="$START_VMID"

while qm status "$VMID" >/dev/null 2>&1; do
  VMID=$((VMID + 1))
done

log "Selected free VMID: ${VMID}"

###############################################################################
# Find available VM name
###############################################################################

VM_NAME="$BASE_NAME"
COUNT=1

while qm list |
      awk 'NR > 1 {print $2}' |
      grep -Fxq "$VM_NAME"; do

  VM_NAME="${BASE_NAME}-${COUNT}"
  COUNT=$((COUNT + 1))
done

log "VM name: ${VM_NAME}"

###############################################################################
# Download Ubuntu cloud image
###############################################################################

if [[ ! -s "$IMG_PATH" ]]; then
  log "Downloading Ubuntu cloud image..."
  log "Source: ${IMG_URL}"

  TEMP_IMG="${IMG_PATH}.part"

  rm -f "$TEMP_IMG"

  wget \
    --tries=5 \
    --timeout=60 \
    --show-progress \
    -O "$TEMP_IMG" \
    "$IMG_URL"

  [[ -s "$TEMP_IMG" ]] ||
    die "Downloaded image is empty."

  mv "$TEMP_IMG" "$IMG_PATH"

  log "Image downloaded: ${IMG_PATH}"
else
  log "Using existing image: ${IMG_PATH}"
fi

###############################################################################
# Create VM with one network interface
###############################################################################

log "Creating VM ${VMID}..."

qm create "$VMID" \
  --name "$VM_NAME" \
  --memory "$MEMORY" \
  --cores "$CORES" \
  --cpu host \
  --net0 "virtio,bridge=${EXTERNAL_BRIDGE}" \
  --ostype l26 \
  --scsihw virtio-scsi-pci \
  --agent enabled=1 \
  --onboot 1

###############################################################################
# Import and attach disk
###############################################################################

log "Importing Ubuntu disk to ${DISK_STORAGE}..."

qm importdisk \
  "$VMID" \
  "$IMG_PATH" \
  "$DISK_STORAGE"

IMPORTED_VOLUME="$(
  qm config "$VMID" |
    awk -F': ' '/^unused0:/ {print $2}' |
    cut -d',' -f1
)"

[[ -n "$IMPORTED_VOLUME" ]] ||
  die "Could not determine imported disk volume."

log "Imported disk volume: ${IMPORTED_VOLUME}"

qm set "$VMID" \
  --scsi0 "$IMPORTED_VOLUME"

log "Resizing disk to ${DISK_SIZE}..."

qm disk resize \
  "$VMID" \
  scsi0 \
  "$DISK_SIZE"

###############################################################################
# Cloud-init disk and boot configuration
###############################################################################

log "Adding cloud-init disk..."

qm set "$VMID" \
  --ide2 "${DISK_STORAGE}:cloudinit"

qm set "$VMID" \
  --boot order=scsi0 \
  --serial0 socket \
  --vga serial0

###############################################################################
# Apply cloud-init configuration
###############################################################################

log "Applying cloud-init network configuration..."

qm set "$VMID" \
  --ipconfig0 "$IMAGE_SERVER_IPCONFIG" \
  --searchdomain cloud.local \
  --ciupgrade 1 \
  --cicustom "user=${ISO_STORAGE}:snippets/${DST_USERDATA}"

if [[ -n "$IMAGE_SERVER_DNS" ]]; then
  qm set "$VMID" \
    --nameserver "$IMAGE_SERVER_DNS"
else
  log "DNS will be provided through DHCP."
fi

qm cloudinit update "$VMID"

###############################################################################
# Display final VM configuration
###############################################################################

echo
echo "================================================================="
echo " VM configuration"
echo "================================================================="

qm config "$VMID"

echo

###############################################################################
# Start VM
###############################################################################

log "Starting VM ${VMID} (${VM_NAME})..."

qm start "$VMID"

log "VM started successfully."

###############################################################################
# Wait for cloud-init poweroff
###############################################################################

if ! wait_for_vm_shutdown "$VMID" 3600; then
  warning "VM did not power off within one hour."
  warning "Cloud-init may still be running or may have failed."
  warning "Check the VM console and:"
  warning "cloud-init status --long"
  exit 1
fi

###############################################################################
# Create clean baseline snapshot
###############################################################################

log "Creating clean baseline snapshot..."

if qm listsnapshot "$VMID" 2>/dev/null |
   grep -q 'First_snapshot'; then

  warning "Snapshot First_snapshot already exists."
else
  qm snapshot \
    "$VMID" \
    First_snapshot \
    --description "Clean baseline snapshot after cloud-init"

  log "Snapshot created successfully."
fi

###############################################################################
# Start VM again
###############################################################################

log "Starting Image Server VM again..."

qm start "$VMID"

trap - ERR

echo
echo "================================================================="
echo " Image Server installation completed"
echo "================================================================="
echo
echo "VMID:        ${VMID}"
echo "VM name:     ${VM_NAME}"
echo "Bridge:      ${EXTERNAL_BRIDGE}"
echo "IP config:   ${IMAGE_SERVER_IPCONFIG}"
echo "DNS:         ${IMAGE_SERVER_DNS:-Provided through DHCP}"
echo "Snapshot:    First_snapshot"
echo "Status:      Started"
echo
echo "Other Proxmox servers must be able to reach the Image Server"
echo "through the net0 address."
echo