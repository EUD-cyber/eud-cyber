#!/bin/bash
set -e

########################################
# FORCE REAL-TIME OUTPUT
########################################
export PYTHONUNBUFFERED=1

########################################
# PATHS
########################################
REPO="./repo.sh"
PREREQ="./pre_req.sh"
OPENVSWITCH="./open-vswitch.sh"

OPNSENSECONF="./OPNSENSE/generate_config.sh"
OPNSENSE="./OPNSENSE/OPNSENSE_installer.sh"

GUACVM_IP="./GUACVM/GUACVM_ip.sh"
GUACVM="./GUACVM/GUACVM_installer.sh"

CLIENT01="./CLIENT01/CLIENT01_installer.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_installer.sh"
KALI01="./KALI01/KALI01_installer.sh"
WAZUH="./WAZUH/WAZUH_installer.sh"
APPSRV01="./APPSRV01/APPSRV01_installer.sh"
WIN2025="./WIN2025/WIN2025_installer.sh"
FINISH="./finish.sh"

########################################
# BACKGROUND CONFIG
########################################
SESSION="proxmox-install"
LOGFILE="/var/log/proxmox-install.log"

########################################
# FOREGROUND PROGRESS
########################################
FG_TOTAL=5
FG_STEP=0

fg_progress() {
  FG_STEP=$((FG_STEP+1))
  echo
  echo "[$FG_STEP/$FG_TOTAL] $1"
  echo "----------------------------------------"
}

########################################
# BACKGROUND WORK
########################################
run_background() {
  STEP=0
  TOTAL=8

  progress() {
    STEP=$((STEP+1))
    echo
    echo "[$STEP/$TOTAL] $1"
    echo "----------------------------------------"
  }

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

  echo
  echo "========================================"
  echo "BACKGROUND INSTALLATION COMPLETED"
  echo "========================================"
}

########################################
# BACKGROUND ENTRYPOINT
########################################
if [ "$1" = "--background" ]; then
  run_background
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
echo "89) Change Proxmox repo to no-subscription"
echo "90) Run FULL install (foreground + background)"
echo "99) Finish"
echo "0) Exit"
echo "=============================="
read -rp "Enter your choice: " CHOICE

########################################
# MENU LOGIC
########################################
case "$CHOICE" in
  1)
    bash "$PREREQ"
    ;;
  2)
    bash "$OPENVSWITCH"
    ;;
  3)
    bash "$OPNSENSECONF"
    bash "$OPNSENSE"
    ;;
  4)
    bash "$GUACVM_IP"
    bash "$GUACVM"
    ;;
  5)
    bash "$VULNSRV01"
    ;;
  6)
    bash "$VULNSRV02"
    ;;
  7)
    bash "$KALI01"
    ;;
  8)
    bash "$WAZUH"
    ;;
  9)
    bash "$WIN2025"
    ;;
  10)
    bash "$APPSRV01"
    ;;
  11)
    bash "$CLIENT01"
    ;;
  89)
    bash "$REPO"
    ;;
  90)
    echo
    echo "===== FOREGROUND PREPARATION PHASE ====="

    fg_progress "Switch Proxmox repo to no-subscription"
    bash "$REPO"

    fg_progress "Check prerequisites & snippets"
    bash "$PREREQ"

    fg_progress "Generate IP configuration"
    bash "$OPNSENSECONF"
    bash "$GUACVM_IP"

    fg_progress "Install Open vSwitch"
    bash "$OPENVSWITCH"

    fg_progress "Create OPNsense VM (blocking)"
    bash "$OPNSENSE"

    echo
    echo "OPNsense installation finished successfully"
    echo "===== STARTING BACKGROUND PHASE ====="
    echo

    command -v tmux >/dev/null || {
      echo "ERROR: tmux is not installed"
      echo "Install with: apt install tmux"
      exit 1
    }

    tmux new-session -d -s "$SESSION" \
      "stdbuf -oL -eL bash $0 --background | tee -a $LOGFILE"

    echo "Background install started"
    echo "Attach with: tmux attach -t $SESSION"
    ;;
  99)
    bash "$FINISH"
    ;;
  0)
    exit 0
    ;;
  *)
    echo "❌ Invalid option"
    ;;
esac
