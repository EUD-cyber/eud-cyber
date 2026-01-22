#!/bin/bash
set -e

########################################
# PATHS
########################################
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
PREREQ="./pre_req.sh"
KALI01="./KALI01/KALI01_installer.sh"
WAZUH="./WAZUH/WAZUH_installer.sh"
WIN2025="./WIN2025/WIN2025_installer.sh"
FINISH="./finish.sh"

########################################
# BACKGROUND CONFIG
########################################
SESSION="proxmox-install"
LOGFILE="/var/log/proxmox-install.log"

########################################
# PROGRESS
########################################
TOTAL_STEPS=13
STEP=0

progress() {
  STEP=$((STEP+1))
  echo ""
  echo "[$STEP/$TOTAL_STEPS] $1"
  echo "----------------------------------------"
}

########################################
# BACKGROUND BOOTSTRAP
########################################
if [ "$1" = "--run-all" ] && [ -z "$INSIDE_TMUX" ]; then
  echo "Starting FULL installation in background"
  echo "tmux session: $SESSION"
  echo "Log file: $LOGFILE"
  echo ""
  echo "Attach with:"
  echo "  tmux attach -t $SESSION"
  echo ""

  tmux new-session -d -s "$SESSION" \
    "INSIDE_TMUX=1 bash $0 --run-all | tee -a $LOGFILE"

  exit 0
fi

########################################
# RUN ALL (OPTION 90)
########################################
run_all() {
  echo "===== PROXMOX FULL LAB INSTALL ====="
  date
  echo "==================================="

  progress "Switch Proxmox repo to no-subscription"
  bash "$REPO"

  progress "Check prerequisites & snippets"
  bash "$PREREQ"

  progress "Generate IP configuration"
  bash "$OPNSENSECONF"
  bash "$GUACVM_IP"

  progress "Install Open vSwitch"
  bash "$OPENVSWITCH"

  progress "Create OPNsense VM (blocking)"
  bash "$OPNSENSE"
  echo "OPNsense installation finished"

  progress "Create Guacamole VM"
  bash "$GUACVM"

  progress "Create Client01 VM"
  bash "$CLIENT01"

  progress "Create Vuln-server01 VM"
  bash "$VULNSRV01"

  progress "Create Vuln-server02 VM"
  bash "$VULNSRV02"

  progress "Create Kali VM"
  bash "$KALI01"

  progress "Create Wazuh VM"
  bash "$WAZUH"

  progress "Create AppSrv01 VM"
  bash "$APPSRV01"

  progress "Create Windows Server 2025 VM"
  bash "$WIN2025"

  progress "Final cleanup"
  bash "$FINISH"

  echo ""
  echo "==================================="
  echo "INSTALLATION COMPLETED SUCCESSFULLY"
  echo "==================================="
  date
}

########################################
# AUTO MODE (NO MENU)
########################################
if [ "$1" = "--run-all" ]; then
  run_all
  exit 0
fi

########################################
# MENU
########################################
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
echo "9) Create Windows Server 2025 VM"
echo "10) Create APPSRV01 VM"
echo "11) Create Client01 VM"
echo "89) Change proxmox repo to no-subscription"
echo "90) Run ALL (background)"
echo "99) Finish"
echo "0) Exit"
echo "=============================="

read -rp "Enter your choice: " CHOICE

case "$CHOICE" in
  1) bash "$PREREQ" ;;
  2) bash "$OPENVSWITCH" ;;
  3) bash "$OPNSENSECONF"; bash "$OPNSENSE" ;;
  4) bash "$GUACVM_IP"; bash "$GUACVM" ;;
  5) bash "$VULNSRV01" ;;
  6) bash "$VULNSRV02" ;;
  7) bash "$KALI01" ;;
  8) bash "$WAZUH" ;;
  9) bash "$WIN2025" ;;
 10) bash "$APPSRV01" ;;
 11) bash "$CLIENT01" ;;
 89) bash "$REPO" ;;
 90) bash "$0" --run-all ;;
 99) bash "$FINISH" ;;
  0) exit 0 ;;
  *) echo "❌ Invalid option" ;;
esac
