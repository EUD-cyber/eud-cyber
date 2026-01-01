#!/bin/bash
set -e

LOGDIR="/var/log/proxmox-lab"
mkdir -p "$LOGDIR"

REPO="./repo.sh"
GUACVM="./GUACVM/GUACVM_installer.sh"
OPENVSWITCH="./open-vswitch.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_installer.sh"
OPNSENSE="./OPNSENSE/OPNSENSE_installer.sh"
PREREQ="./pre_req.sh"
KALI01="./KALI01/KALI01_installer.sh"
WAZUH="./WAZUH/WAZUH_installer.sh"
WIN11="./WIN11/WIN11_installer.sh"
WIN2025="./WIN2025/WIN2025_installer.sh"
FINISH="./finish.sh"

spinner() {
  local pid=$1
  local text=$2
  local spin='-\|/'
  local i=0

  printf " ⏳ %s " "$text"

  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\b${spin:$i:1}"
    sleep 0.2
  done
}

run_step() {
  local name="$1"
  local script="$2"
  local logfile="$LOGDIR/${name}.log"

  echo
  echo "----------------------------------------"
  echo " STARTING: $name"
  echo " LOG: $logfile"
  echo "----------------------------------------"

  bash "$script" >"$logfile" 2>&1 &
  local pid=$!

  spinner "$pid" "$name"

  wait "$pid"
  local rc=$?

  if [[ $rc -eq 0 ]]; then
    printf "\r ✔ %s completed successfully\n" "$name"
  else
    printf "\r ✖ %s FAILED (see %s)\n" "$name" "$logfile"
  fi

  return $rc
}

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
echo "89) Change proxmox repo to no-enterprise"
echo "90) Run ALL (status + logs)"
echo "99) Finish script"
echo "0) Exit"
echo "=============================="

read -rp "Enter your choice: " CHOICE

case "$CHOICE" in
  1) run_step "PREREQ" "$PREREQ" ;;
  2) run_step "Open vSwitch" "$OPENVSWITCH" ;;
  3) run_step "OPNsense" "$OPNSENSE" ;;
  4) run_step "Guacamole VM" "$GUACVM" ;;
  5) run_step "Vuln-server01" "$VULNSRV01" ;;
  6) run_step "Vuln-server02" "$VULNSRV02" ;;
  7) run_step "KALI01" "$KALI01" ;;
  8) run_step "Wazuh" "$WAZUH" ;;
  9) run_step "Windows 11" "$WIN11" ;;
  89) run_step "Proxmox repo change" "$REPO" ;;
  99) run_step "Finish Script" "$FINISH" ;;
  90)
    echo
    echo "🚀 Running full deployment with status…"
    echo "Logs stored in: $LOGDIR"
    echo

    run_step "Proxmox repo change" "$REPO"
    run_step "PREREQ" "$PREREQ"
    run_step "Open vSwitch" "$OPENVSWITCH"

    # ---- OPNsense (required before others) ----
    if run_step "OPNsense" "$OPNSENSE"; then
      OPNSENSE_OK=true
    else
      echo "❌ OPNsense failed — stopping dependent installs."
    fi

    # ---- only continue if OPNsense succeeded ----
    if $OPNSENSE_OK; then

      wait_for_opnsense   # (function below)

      run_step "Guacamole VM" "$GUACVM"
      run_step "Vuln-server01" "$VULNSRV01"
      run_step "Vuln-server02" "$VULNSRV02"
      run_step "KALI01" "$KALI01"
      run_step "Wazuh" "$WAZUH"
    fi

    run_step "Finish Script" "$FINISH"
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
