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

FULL_INSTALL="./full_install.sh"
MINI_INSTALL="./mini_install.sh"
MULTI_INSTALL="./multi_install.sh"
MULTI_INSTALL_MINI="./multi_mini_install.sh"

clear
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

