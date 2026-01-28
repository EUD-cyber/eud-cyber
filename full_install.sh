#!/bin/bash
set -e

REPO="./repo.sh"
GUACVM_IP="./GUACVM/GUACVM_ip.sh"
GUACVM="./GUACVM/GUACVM_installer.sh"
OPENVSWITCH="./open-vswitch.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_installer.sh"
OPNSENSE="./OPNSENSE/OPNSENSE_installer.sh"
OPNSENSECONF="./OPNSENSE/generate_config.sh"
APPSRV01="./APPSRV01/APPSRV01_installer.sh"
CLIENT01="./CLIENT01/CLIENT01_installer.sh"
PACKETFENCE="./PACKETFENCE/PACKETFENCE_installer.sh"
PREREQ="./pre_req.sh"
KALI01="./KALI01/KALI01_installer.sh"
WAZUH="./WAZUH/WAZUH_installer.sh"
WIN11="./WIN11/WIN11_installer.sh"
WIN2025="./WIN2025/WIN2025_installer.sh"
FINISH="./finish.sh"

echo "=============================="
echo " Proxmox Deployment Menu"
echo "=============================="
echo "1) Check packages & snippets (PREREQ)"
echo "2) Install & configure Open vSwitch"
echo "3) Create OPNsense VM"
echo "4) Create Guacamole VM"
echo "5) Create Vuln-server01 VM"
echo "6) Create Vuln-server02 VM"
echo "7) Create KALI01 VM"
echo "8) Create WAZUH VM"
echo "9) Create Windows 11 VM"
echo "10) Create Windows server 2025 VM"
echo "11) Create APPSRV01 VM"
echo "12) Create Client01 VM"
echo "89) Change proxmox repo to no-enterprise"
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
    bash "$OPNSENSECONF"
    bash "$OPNSENSE"
    ;;
  4)
    echo "Starting Guacamole VM creation..."
    bash "$GUACVM_IP"
    bash "$GUACVM"
    ;;
  5)
    echo "Starting Vuln-server01 VM creation..."
    bash "$VULNSRV01"
    ;;
  6)
    echo "Stating Vuln-server02 VM creation..."
    bash "$VULNSRV02"
    ;;
  7)
    echo "Starting KALI01 VM creation... "
    bash "$KALI01"
    ;;
  8)
    echo "Starting Wazuh VM creation.... "
    bash "$WAZUH"
    ;;
  9)
    echo "Starting Windows 11 VM creation... "
    bash "$WIN11"
    ;;
 10)
    echo "Starting Windows server 2025 VM creation... "
    bash "$WIN2025"
    ;;
  11)
    echo "Starting APPSRV01 VM creation.... "
    bash "$APPSRV01"
    ;;
  12)
    echo "Staring Client01 VM creation... "
    bash "$CLIENT01"
    ;;
  89)
    echo "Change proxmox repo to no-enterprise"
    bash "$REPO"
    ;;
  90)
    echo "Running ALL steps..."
    
    echo "Change proxmox repo to no-enterprise"
    bash "$REPO"
    
    echo "Checking packages and snippets..."
    bash "$PREREQ"

    echo "IP settings on Guacamole and Opnsense"
    bash "$OPNSENSECONF"
    bash "$GUACVM_IP"
    
    echo "Starting Open vSwitch installation and configuration"
    bash "$OPENVSWITCH"

    echo "Starting OPNsense VM creation..."
    bash "$OPNSENSE"

    echo "Starting Guacamole VM creation..."
    bash "$GUACVM"

    echo "Staring Client01 VM creation..."
    bash "$CLIENT01"

    echo "Starting Vuln-server01 VM creation..."
    bash "$VULNSRV01"

    echo "Starting Vuln-server02 VM creation..."
    bash "$VULNSRV02"
    
    echo "Starting KALI01 VM creation... "
    bash "$KALI01"

    echo "Starting Wazuh VM creation... "
    bash "$WAZUH"

    echo "Starting APPSRV01 creation... "
    bash "$APPSRV01"
    
#    echo "Starting Windows 11 VM creation... "
#    bash "$WIN11"

     echo "Starting Windows server 2025 VM creation.... "
     bash "$WIN2025"
    
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
