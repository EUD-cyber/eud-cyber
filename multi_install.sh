#!/bin/bash
set -e

REPO="./repo.sh"
GUACVM_IP="./GUACVM/GUACVM_ip.sh"
GUACVM="./GUACVM/GUACVM_installer.sh"
OPENVSWITCHPRE="./open-vswitch-multi-pre.sh"
OPENVSWITCH="./open-vswitch-multi.sh"
OPENVSWITCHLAST="./open-vswitch-multi-last.sh"
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

  
# =========================
# Menu
# =========================
echo "=============================="
echo " Multi Lab Installer"
echo "=============================="
echo "A) Prepare N labs (OVS + config)"
echo "0) Exit"
echo "=============================="

read -rp "Enter your choice: " CHOICE

# =========================
# Case
# =========================
case "$CHOICE" in

  A|a)
    read -rp "How many labs to prepare (1–16): " LABCOUNT

    if ! [[ "$LABCOUNT" =~ ^[0-9]+$ ]] || [ "$LABCOUNT" -lt 1 ] || [ "$LABCOUNT" -gt 16 ]; then
      echo "❌ Invalid number. Must be between 1 and 16."
      exit 1
    fi

    echo "===== Base setup (run once) ====="
    bash "$REPO" || exit 1
    bash "$PREREQ" || exit 1

    echo "===== Open vSwitch pre ====="
    bash "$OPENVSWITCHPRE" || exit 1

    echo "===== Phase 1: OVS (all labs) ====="
    for i in $(seq 1 "$LABCOUNT"); do
      echo "Creating OVS bridges for lab $i"
      bash "$OPENVSWITCH" "$i" || exit 1
    done

    echo "===== Open vSwitch post ====="
    bash "$OPENVSWITCHLAST" || exit 1

    echo "===== Phase 2: Lab configs ====="
    for i in $(seq 1 "$LABCOUNT"); do
      echo "Lab $i configs"
      bash "$OPNSENSECONF" || exit 1
      bash "$GUACVM_IP" || exit 1
    done

    echo "✅ $LABCOUNT labs prepared successfully"
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
