#!/bin/bash
set -e

FULL_INSTALL="./full_install.sh"
MINI_INSTALL="./mini_install.sh"
MULTI_INSTALL="./multi_install.sh"

clear
echo "===================================="
echo "        Proxmox Deployment"
echo "===================================="
echo "1) Standalone Proxmox (Full Lab)"
echo "2) Standalone Proxmox (Mini Lab low spec)"
echo "3) Single Proxmox Cluster (multilabs on same proxmox"
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
    echo "▶ Single Proxmox Cluster (multilabs on same proxmox"
    bash "$MULTI_INSTALL"
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

