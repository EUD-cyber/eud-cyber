#!/bin/bash
set -e

LINUX_IMG=""https://cloud-images.ubuntu.com/noble/20260217/noble-server-cloudimg-amd64.img""
OPNSENSE_IMG=""
WAZUH_IMG=""
KALI_IMG=""
WIN2025_IMG=""


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

