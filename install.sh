#!/bin/bash
set -e


GUACVM="./GUACVM/GUACVM_installer.sh"
OPENVSWITCH="./open-vswitch.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_installer.sh"
OPNSENSE="./OPENSENSE/OPNSENSE_installer.sh"
PREREQ="./pre_req.sh"
KALI01="./KALI01/KALI01_installer.sh"
WAZUH="./WAZUH/WAZUH_installer.sh"
FINISH="./finish.sh"

echo "=============================="
echo " Proxmox Deployment Menu"
echo "=============================="
echo "1) Check packages & snippets (PREREQ)"
echo "2) Install & configure Open vSwitch"
echo "3) Create OPNsense VM"
echo "4) Create Guacamole VM"
echo "5) Create Vuln-server01 VM"
echo "6) Create KALI01 VM"
echo "7) Create WAZUH VM"
echo "90) Run ALL"
echo "99) Finish script"
echo "0) Exit"
echo "=============================="

read -rp "Enter your choice: " CHOICE

case "$CHOICE" in
  1)
    echo "Checking packages and snippets..."
    bash "$PREREQ"
    ;;
  2)
    echo "Starting Open vSwitch installation and configuration"
    bash "$OPENVSWITCH"
    ;;
  3)
    echo "Starting OPNsense VM creation..."
    bash "$OPNSENSE"
    ;;
  4)
    echo "Starting Guacamole VM creation..."
    bash "$GUACVM"
    ;;
  5)
    echo "Starting Vuln-server01 VM creation..."
    bash "$VULNSRV01"
    ;;
  6)
    echo "Starting KALI01 VM creation... "
    bash "$KALI01"
    ;;
  7)
    echo "Starting Wazuh VM creation.... "
    bash "$WAZUH"
    ;;
  90)
    echo "Running ALL steps..."

    echo "Checking packages and snippets..."
    bash "$PREREQ"

    echo "Starting Open vSwitch installation and configuration"
    bash "$OPENVSWITCH"

    echo "Starting OPNsense VM creation..."
    bash "$OPNSENSE"

    echo "Starting Guacamole VM creation..."
    bash "$GUACVM"

    echo "Starting Vuln-server01 VM creation..."
    bash "$VULNSRV01"

    echo "Starting KALI01 VM creation... "
    bash "$KALI01"

    echo "Stating Wazuh VM creation... "
    bash "$WAZUH"

    echo "Start finishing script..."
    bash "$FINISH"
    ;;
  0)
    echo "Exiting."
    exit 0
    ;;
  99)
    echo "Start finishing script..."
    bash "$FINISH"
    ;;
  *)
    echo "❌ Invalid choice"
    exit 1
    ;;
esac


