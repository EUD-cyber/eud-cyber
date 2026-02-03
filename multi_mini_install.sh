#!/bin/bash
set -e

REPO="./repo.sh"
GUACVM_IP="./GUACVM/GUACVM_ip_multi.sh"
GUACVM="./GUACVM/GUACVM_multi_installer.sh"
OPENVSWITCHPRE="./open-vswitch-multi-pre.sh"
OPENVSWITCH="./open-vswitch-multi.sh"
OPENVSWITCHLAST="./open-vswitch-multi-last.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_mini_multi_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_mini_multi_installer.sh"
OPNSENSE="./OPNSENSE/OPNSENSE_mini_multi_installer.sh"
OPNSENSECONF="./OPNSENSE/generate_config_multi.sh"
APPSRV01="./APPSRV01/APPSRV01_mini_multi_installer.sh"
CLIENT01="./CLIENT01/CLIENT01_mini_multi_installer.sh"
PACKETFENCE="./PACKETFENCE/PACKETFENCE_installer.sh"
PREREQ="./pre_req.sh"
KALI01="./KALI01/KALI01_mini_multi_installer.sh"
WAZUH="./WAZUH/WAZUH_mini_multi_installer.sh"
WIN11="./WIN11/WIN11_installer.sh"
WIN2025="./WIN2025/WIN2025_mini_multi_installer.sh"

    read -rp "How many labs to prepare (1–16): " LABCOUNT

    if ! [[ "$LABCOUNT" =~ ^[0-9]+$ ]] || [ "$LABCOUNT" -lt 1 ] || [ "$LABCOUNT" -gt 16 ]; then
      echo "❌ Invalid number. Must be between 1 and 16."
      exit 1
    fi

    echo
    echo "===== Preparing $LABCOUNT labs ($SPEC spec) ====="

    # -------------------------
    # Base setup (once)
    # -------------------------
    echo "Change proxmox repo to no-enterprise"
    bash "$REPO" || exit 1

    echo "Checking packages and snippets..."
    bash "$PREREQ" || exit 1

    echo "===== Open vSwitch pre ====="
    bash "$OPENVSWITCHPRE" || exit 1

    # -------------------------
    # Phase 1: OVS (all labs)
    # -------------------------
    echo "===== Creating Open vSwitch bridges ====="
    for i in $(seq 1 "$LABCOUNT"); do
      echo "Creating OVS bridges for lab $i"
      bash "$OPENVSWITCH" "$i" || exit 1
    done

    echo "===== Open vSwitch post ====="
    bash "$OPENVSWITCHLAST" || exit 1

    # -------------------------
    # Phase 2: Lab configs
    # -------------------------
    echo "===== Creating lab configs ====="
    for i in $(seq 1 "$LABCOUNT"); do
      echo
      echo "----- Lab $i ($SPEC) -----"

     bash "$OPNSENSECONF" "$i" || exit 1
     bash "$GUACVM_IP" "$i" || exit 1
    done
    echo
    echo "✅ $LABCOUNT labs prepared ($SPEC spec)"
    # -------------------------
    # Phase 3: Install OPNsense VMs
    # -------------------------
    echo
    echo "===== Installing OPNsense VMs ====="
    
    for i in $(seq 1 "$LABCOUNT"); do
      echo "Installing OPNsense for lab $i"
      bash "$OPNSENSE" "$i" || exit 1
    done


# -------------------------
# Phase 4: Install remaining VMs in tmux (per lab, SERIALIZED)
# -------------------------
echo
echo "===== Installing remaining VMs in tmux ====="

if ! command -v tmux >/dev/null 2>&1; then
  echo "❌ tmux not installed. Install with: apt install tmux"
  exit 1
fi

for i in $(seq 1 "$LABCOUNT"); do
  SESSION="lab${i}"
  PREV=$((i - 1))
  WAIT_CMD=""

  if (( i > 1 )); then
    WAIT_CMD="tmux wait-for lab${PREV}_done"
  fi

  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "⚠ tmux session '$SESSION' already exists, skipping"
    continue
  fi

  echo "Starting background installs for lab $i in tmux session '$SESSION'"

  tmux new-session -d -s "$SESSION" bash -c "
  set -e
  trap 'tmux wait-for -S lab${i}_done' EXIT
  exec > >(tee -a lab${i}.log) 2>&1

    echo '===== Lab $i background deployment started at \$(date) ====='

    $WAIT_CMD

    echo 'Starting Guacamole VM creation'
    bash '$GUACVM' '$i'

    echo 'Starting Client01 VM creation'
    bash '$CLIENT01' '$i'

    echo 'Starting Vuln-server01 VM creation'
    bash '$VULNSRV01' '$i'

    echo 'Starting Vuln-server02 VM creation'
    bash '$VULNSRV02' '$i'
    
    echo 'Starting KALI01 VM creation'
    bash '$KALI01' '$i'

    echo 'Starting Wazuh VM creation'
    bash '$WAZUH' '$i'

    echo 'Starting APPSRV01 creation'
    bash '$APPSRV01' '$i'

    echo '===== Lab $i background deployment completed at \$(date) ====='

    
    echo 'Signaled lab${i}_done'

    exit 0
  "
done

echo
echo "All background installs started."
echo "Attach with: tmux attach -t labX (e.g. lab1)"
