#!/bin/bash
set -e

LAB="1"
REPO="./repo.sh"
#GUACVM_IP="./GUACVM/GUACVM_ip.sh"
GUACVM_IP="./GUACVM/GUACVM_ip_multi.sh"
#GUACVM="./GUACVM/GUACVM_installer.sh"
GUACVM="./GUACVM/GUACVM_multi_installer.sh"
#OPENVSWITCH="./open-vswitch.sh"
OPENVSWITCHPRE="./open-vswitch-multi-pre.sh"
OPENVSWITCH="./open-vswitch-multi.sh"
OPENVSWITCHLAST="./open-vswitch-multi-last.sh"
#VULNSRV01="./VULNSRV01/VULNSRV01_installer.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_multi_installer.sh"
#VULNSRV02="./VULNSRV02/VULNSRV02_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_multi_installer.sh"
#OPNSENSE="./OPNSENSE/OPNSENSE_installer.sh"
OPNSENSE="./OPNSENSE/OPNSENSE_multi_installer.sh"
#OPNSENSECONF="./OPNSENSE/generate_config.sh"
OPNSENSECONF="./OPNSENSE/generate_config_multi.sh"
#APPSRV01="./APPSRV01/APPSRV01_installer.sh"
APPSRV01="./APPSRV01/APPSRV01_multi_installer.sh"
#CLIENT01="./CLIENT01/CLIENT01_installer.sh"
CLIENT01="./CLIENT01/CLIENT01_multi_installer.sh"
PACKETFENCE="./PACKETFENCE/PACKETFENCE_installer.sh"
PREREQ="./pre_req.sh"
#KALI01="./KALI01/KALI01_installer.sh"
KALI01="./KALI01/KALI01_multi_installer.sh"
#WAZUH="./WAZUH/WAZUH_installer.sh"
WAZUH="./WAZUH/WAZUH_multi_installer.sh"
WIN11="./WIN11/WIN11_installer.sh"
#WIN2025="./WIN2025/WIN2025_installer.sh"
WIN2025="./WIN2025/WIN2025_multi_installer.sh"

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
echo "95) Run ALL in background"
echo "99) Cleanup all installation"
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
    #bash "$OPENVSWITCH"
    bash $OPENVSWITCHPRE 
    bash $OPENVSWITCH $LAB
    bash $OPENVSWITCHLAST 
    ;;
  3)
    echo "Starting OPNsense VM creation..."
    bash "$OPNSENSECONF" $LAB
    bash "$OPNSENSE" $LAB
    ;;
  4)
    echo "Starting Guacamole VM creation..."
    bash "$GUACVM_IP" $LAB
    bash "$GUACVM" $LAB
    ;;
  5)
    echo "Starting Vuln-server01 VM creation..."
    bash "$VULNSRV01" $LAB
    ;;
  6)
    echo "Stating Vuln-server02 VM creation..."
    bash "$VULNSRV02" $LAB
    ;;
  7)
    echo "Starting KALI01 VM creation... "
    bash "$KALI01" $LAB
    ;;
  8)
    echo "Starting Wazuh VM creation.... "
    bash "$WAZUH" $LAB
    ;;
  9)
    echo "Starting Windows 11 VM creation... "
    bash "$WIN11" $LAB
    ;;
 10)
    echo "Starting Windows server 2025 VM creation... "
    bash "$WIN2025" $LAB
    ;;
  11)
    echo "Starting APPSRV01 VM creation.... "
    bash "$APPSRV01" $LAB
    ;;
  12)
    echo "Staring Client01 VM creation... "
    bash "$CLIENT01" $LAB
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
    bash "$OPNSENSECONF" $LAB
    bash "$GUACVM_IP" $LAB
    
    echo "Starting Open vSwitch installation and configuration"
    #bash "$OPENVSWITCH" $LAB
    bash $OPENVSWITCHPRE 
    bash $OPENVSWITCH $LAB
    bash $OPENVSWITCHLAST

    echo "Starting OPNsense VM creation..."
    bash "$OPNSENSE" $LAB

    echo "Starting Guacamole VM creation..."
    bash "$GUACVM" $LAB

    echo "Staring Client01 VM creation..."
    bash "$CLIENT01" $LAB

    echo "Starting Vuln-server01 VM creation..."
    bash "$VULNSRV01" $LAB

    echo "Starting Vuln-server02 VM creation..."
    bash "$VULNSRV02" $LAB
    
    echo "Starting KALI01 VM creation... "
    bash "$KALI01" $LAB

    echo "Starting Wazuh VM creation... "
    bash "$WAZUH" $LAB

    echo "Starting APPSRV01 creation... "
    bash "$APPSRV01" $LAB
    
     echo "Starting Windows server 2025 VM creation.... "
     bash "$WIN2025" $LAB
     ;;
  95)
  SESSION="deploy-all"

  echo "===== Phase 1: Interactive configuration ====="
  
  bash "$OPNSENSECONF" $LAB" || exit 1
  bash "$GUACVM_IP" $LAB || exit 1

  echo "===== Phase 2: Run OPNsense installer (expect, outside tmux) ====="
  bash "$OPNSENSE" $LAB || exit 1

  if ! command -v tmux >/dev/null 2>&1; then
    echo "❌ tmux not installed. Install with: apt install tmux"
    exit 1
  fi

  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "❌ tmux session '$SESSION' already exists."
    echo "Attach with: tmux attach -t $SESSION"
    exit 1
  fi

  echo "===== Phase 3: Starting remaining installs in background (tmux) ====="

  tmux new-session -d -s "$SESSION" bash -c "
    set -e
    exec > >(tee -a deploy.log) 2>&1

    echo 'Change proxmox repo to no-enterprise'
    bash '$REPO'

    echo 'Checking packages and snippets...'
    bash '$PREREQ'
    
    echo 'Starting Open vSwitch installation and configuration'
    bash $OPENVSWITCHPRE 
    bash $OPENVSWITCH $LAB
    bash $OPENVSWITCHLAST 

    echo 'Starting Guacamole VM creation'
    bash '$GUACVM' $LAB

    echo 'Starting Client01 VM creation'
    bash '$CLIENT01' $LAB

    echo 'Starting Vuln-server01 VM creation'
    bash '$VULNSRV01' $LAB

    echo 'Starting Vuln-server02 VM creation'
    bash '$VULNSRV02' $LAB

    echo 'Starting KALI01 VM creation'
    bash '$KALI01' $LAB

    echo 'Starting Wazuh VM creation'
    bash '$WAZUH' $LAB

    echo 'Starting APPSRV01 creation'
    bash '$APPSRV01' $LAB

    echo 'Starting Windows server 2025 VM creation'
    bash '$WIN2025' $LAB 

    echo '===== Deployment completed successfully ====='
  "

  echo "Deployment running in background tmux session: $SESSION"
  echo "Attach anytime with: tmux attach -t $SESSION"
  echo "Check logs with: tail -f deploy.log"

  exit 0
  ;;


  99)
     rm -rf ./eud-cyber
     rm -rf /var/lib/vz/snippets/*
     rm -rf /var/lib/vz/template/iso/*
     ;;
  0)
    echo "Exiting."
    exit 0
    ;;
  *)
    echo "❌ Invalid choice"
    exit 1
    ;;
esac
