#!/bin/bash
set -e

# =========================
# OVERRIDE URLS
# =========================

CUSTOM_LINUX_IMG="https://cloud-images.ubuntu.com/noble/20260217/noble-server-cloudimg-amd64.img"
CUSTOM_WAZUH_IMG="https://packages.wazuh.com/4.x/vm/wazuh-4.14.1.ova"
CUSTOM_KALI_IMG="https://kali.download/cloud-images/kali-2025.4/kali-linux-2025.4-cloud-genericcloud-amd64.tar.xz"

# OPNSENSE uses version only (no URL check needed here)
OPNSENSE_VERSION="26.1.2"
export OPNSENSE_VERSION


# =========================
# FUNCTION: Try export override
# =========================

try_export() {
    VAR_NAME="$1"
    URL="$2"

    if wget --spider --quiet --timeout=10 "$URL"; then
        echo "✔ $VAR_NAME override reachable — using override"
        export "$VAR_NAME=$URL"
    else
        echo "⚠ $VAR_NAME override not reachable — using default"
    fi
}

# =========================
# APPLY OVERRIDES
# =========================

try_export LINUX_IMG "$CUSTOM_LINUX_IMG"
try_export WAZUH_IMG "$CUSTOM_WAZUH_IMG"
try_export KALI_IMG "$CUSTOM_KALI_IMG"

#!/bin/bash

echo "Detecting available Proxmox storage..."

# Get ISO-capable storage
mapfile -t ISO_LIST < <(pvesm status --content iso | awk 'NR>1 {print $1}')

# Get VM disk-capable storage
mapfile -t DISK_LIST < <(pvesm status --content images | awk 'NR>1 {print $1}')

# Safety check
if [[ ${#ISO_LIST[@]} -eq 0 ]]; then
    echo "ERROR: No ISO-capable storage found."
    exit 1
fi

if [[ ${#DISK_LIST[@]} -eq 0 ]]; then
    echo "ERROR: No VM disk-capable storage found."
    exit 1
fi

# -------- ISO Selection --------
echo ""
echo "Available ISO storages:"
select ISO_STORAGE in "${ISO_LIST[@]}"; do
    if [[ -n "$ISO_STORAGE" ]]; then
        break
    fi
done

# -------- Disk Selection --------
echo ""
echo "Available VM disk storages:"
select DISK_STORAGE in "${DISK_LIST[@]}"; do
    if [[ -n "$DISK_STORAGE" ]]; then
        break
    fi
done

# Export as requested
export LOCAL="$ISO_STORAGE"
export LVM="$DISK_STORAGE"

echo ""
echo "ISO storage selected: $LOCAL"
echo "Disk storage selected: $LVM"
echo "Variables exported: LOCAL and LVM"

FULL_INSTALL="./full_install.sh"
MINI_INSTALL="./mini_install.sh"
MULTI_INSTALL="./multi_install.sh"
MULTI_INSTALL_MINI="./multi_mini_install.sh"


echo "===================================="
echo "        Proxmox Deployment"
echo "===================================="
echo "1) Standalone Proxmox (Full Lab)"
echo "2) Standalone Proxmox (Mini Lab low spec)"
echo "3) Multilabs full spec on same proxmox"
echo "4) Multilabs mini spec on same proxmox"
echo "0) Exit"
echo "===================================="
read -rp "Select deployment type: " choice

case "$choice" in

  1)
    echo "▶ Standalone Proxmox (Full Lab)"
    bash "$FULL_INSTALL"
    ;;

  2)
    echo "▶ Standalone Proxmox (Mini Lab low spec)"
    bash "$MINI_INSTALL"
    ;;

  3)
    echo "▶ Multilabs full spec on same proxmox"
    bash "$MULTI_INSTALL"
    ;;
  4)
    echo "▶ Multilabs mini spec on same proxmox"
    bash "$MULTI_INSTALL_MINI"
    ;;
  0)
    echo "Exiting..."
    exit 0
    ;;

  *)
    echo "Invalid option"
    exit 1
    ;;
esac

