#!/usr/bin/env bash
set +x
set -Eeuo pipefail
IFS=$'\n\t'

LAB="${1:-}"
[[ "$LAB" =~ ^([1-9]|1[0-6])$ ]] || { echo "Usage: $0 <lab-number 1-16>" >&2; exit 1; }
START_VMID=$((LAB * 1000))
BASE_NAME="lab${LAB}-WAZUH"
MEMORY="${WAZUH_MEM:-16384}"
CORES="${WAZUH_CPU:-4}"
DISK_SIZE="${WAZUH_HDD:-100G}"
BRIDGE="lab${LAB}_lan2"
BRIDGE1="lab${LAB}_oobm"
ISO_STORAGE="${LOCAL:-local}"
DISK_STORAGE="${LVM:-local-lvm}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
umask 077
mkdir -p LOGS
exec 7>"LOGS/WAZUH_lab${LAB}.lock"
flock -n 7 || { echo 'WAZUH installation already running for this lab.' >&2; exit 1; }
LOGFILE="$(mktemp "LOGS/WAZUH_lab${LAB}_$(date -u +%Y%m%dT%H%M%SZ).XXXXXX.log")"
exec > >(tee -a "$LOGFILE") 2>&1
VMID=''
trap 'rc=$?; echo "WAZUH failed at line $LINENO (exit $rc); VMID=${VMID:-not-created}. See $LOGFILE. Existing VMs are never removed." >&2; exit "$rc"' ERR
[[ "$EUID" -eq 0 ]] || { echo 'Run as root on Proxmox.' >&2; exit 1; }
[[ "$MEMORY" =~ ^[1-9][0-9]*$ && "$CORES" =~ ^[1-9][0-9]*$ && "$DISK_SIZE" =~ ^[1-9][0-9]*[GMT]$ ]] || exit 1
(( MEMORY >= 8192 && CORES >= 4 )) || { echo 'WAZUH requires >=4 vCPU and >=8192 MiB RAM.' >&2; exit 1; }
PASSWORD_FILE="${WAZUH_ADMIN_PASSWORD_FILE:-/etc/cyberlab/wazuh-admin-password}"
if [[ -z "${WAZUH_ADMIN_PASSWORD_FILE:-}" && ! -e "$PASSWORD_FILE" && ! -L "$PASSWORD_FILE" ]]; then
  PASSWORD_FILE="$SCRIPT_DIR/wazuh-admin-password"
  # Git checkouts do not preserve the owner's read/write-only mode.
  if [[ -f "$PASSWORD_FILE" && ! -L "$PASSWORD_FILE" && -O "$PASSWORD_FILE" ]]; then
    chmod 600 -- "$PASSWORD_FILE"
  fi
fi
if [[ ! -f "$PASSWORD_FILE" || -L "$PASSWORD_FILE" || "$(stat -c '%u:%a' -- "$PASSWORD_FILE")" != 0:600 ]]; then
  echo 'WAZUH requires a root-owned admin password file in /etc/cyberlab or beside WAZUH_installer.sh.' >&2
  exit 1
fi
if ! python3 -c '
import re, sys
p = sys.stdin.buffer.read(67).rstrip(b"\r\n")
symbols = rb"[.,_+:@%^=~-]"
valid = re.fullmatch(rb"[A-Za-z0-9.,_+:@%^=~-]{12,64}", p)
sys.exit(not (valid and not sys.stdin.buffer.read(1)
              and all(re.search(rule, p) for rule in (rb"[a-z]", rb"[A-Z]", rb"[0-9]", symbols))))
' <"$PASSWORD_FILE"; then
  echo 'WAZUH admin password file does not meet the RC2 password policy.' >&2
  exit 1
fi
# Fail closed on a duplicate component; never append a suffix and reuse its IP.
VMID="$(pvesh get /cluster/resources --type vm --output-format json | python3 -c '
import json, sys
guests=json.load(sys.stdin)
if not isinstance(guests, list) or any(not isinstance(vm, dict) for vm in guests):
    sys.exit("Invalid cluster VM inventory; no VM created.")
name = sys.argv[1].lower()
reserved = {name, name + "5x", name + "_old"}
for vm in guests:
    guest_name = str(vm.get("name", "")).lower().split("-", 2)
    if "-".join(guest_name[:2]) in reserved:
        sys.exit("WAZUH already exists in this lab; no VM created.")
start=int(sys.argv[2])
used={int(vm["vmid"]) for vm in guests if "vmid" in vm}
for candidate in range(start, start + 1000):
    if candidate not in used:
        print(candidate)
        break
else:
    sys.exit("No free VMID in the selected lab range; no VM created.")
' "$BASE_NAME" "$START_VMID")"
echo "Selected free VMID for lab${LAB}: $VMID"
ip link show "$BRIDGE" >/dev/null
ip link show "$BRIDGE1" >/dev/null
# Resolve the actual selected snippet storage, including non-default paths.
DST_USERDATA="WAZUH_rc2_userdata_lab${LAB}.yaml"
DST_PATH="$(pvesm path "${ISO_STORAGE}:snippets/${DST_USERDATA}")"
mkdir -p -- "$(dirname -- "$DST_PATH")"
# Use the same ubuntu/password cloud-init login as the other Ubuntu lab VMs.
# The guest bootstrap rotates the Wazuh Dashboard/Indexer admin account.
cp -- "$SCRIPT_DIR/WAZUH_userdata.yaml" "$DST_PATH"
chmod 600 "$DST_PATH"
source ./ubuntu2604-image.sh
fetch_ubuntu2604
qm create "$VMID" --name "$BASE_NAME" --memory "$MEMORY" --cores "$CORES" --cpu host \
  --net0 "virtio,bridge=$BRIDGE" --net1 "virtio,bridge=$BRIDGE1" --ostype l26
qm importdisk "$VMID" "$IMG_PATH" "$DISK_STORAGE"
VOLUME="$(qm config "$VMID" | sed -n 's/^unused0: //p')"
[[ -n "$VOLUME" ]]
qm set "$VMID" --scsihw virtio-scsi-pci --scsi0 "$VOLUME" --ide2 "$DISK_STORAGE:cloudinit" \
  --boot order=scsi0 --agent enabled=1 --onboot 1 \
  --ipconfig0 ip=192.168.2.20/24,gw=192.168.2.1 --ipconfig1 ip=172.20.0.20/24 \
  --searchdomain cloud.local --nameserver 192.168.2.1 --ciupgrade 0 \
  --cicustom "user=$ISO_STORAGE:snippets/$DST_USERDATA"
qm disk resize "$VMID" scsi0 "+$DISK_SIZE"
qm start "$VMID"
# Only snapshot after the guest explicitly reports a successful health check.
deadline=$((SECONDS + ${WAZUH_BOOT_TIMEOUT:-3600}))
password_delivered=0
while (( SECONDS < deadline )); do
  if qm guest exec "$VMID" -- /usr/bin/test -f /var/lib/wazuh5x/bootstrap.failed 2>/dev/null | grep -qE '"exitcode"[[:space:]]*:[[:space:]]*0'; then
    echo "Guest bootstrap failed; inspect /var/log/wazuh5x/ in VM $VMID." >&2; exit 1
  fi
  if [[ "$(qm status "$VMID" | awk '{print $2}')" == stopped ]]; then
    qm start "$VMID"
    password_delivered=0
  fi
  if (( ! password_delivered )); then
    if qm guest exec "$VMID" --pass-stdin 1 -- /bin/bash +x -c '
      set -eu
      umask 077
      tmp=$(mktemp /var/lib/wazuh5x/.admin-password.XXXXXX)
      trap '\''rm -f -- "$tmp"'\'' EXIT
      cat >"$tmp"
      mv -f -- "$tmp" /var/lib/wazuh5x/admin-password
    ' <"$PASSWORD_FILE" 2>/dev/null | grep -qE '"exitcode"[[:space:]]*:[[:space:]]*0'; then
      password_delivered=1
    else
      sleep 15
      continue
    fi
  fi
  if qm guest exec "$VMID" -- /usr/local/sbin/wazuh5x-healthcheck 2>/dev/null | grep -qE '"exitcode"[[:space:]]*:[[:space:]]*0'; then
    qm shutdown "$VMID" --timeout 120
    [[ "$(qm status "$VMID" | awk '{print $2}')" == stopped ]]
    qm snapshot "$VMID" First_snapshot --description 'WAZUH RC2 Ubuntu 26.04 healthy baseline'
    qm start "$VMID"
    echo "WAZUH ready: VM $VMID; https://172.20.0.20 or GUACVM:3001. Credentials: /etc/wazuh-indexer/export/credentials.env (root only)."
    exit 0
  fi
  sleep 15
done
echo "Timed out waiting for WAZUH health. VM $VMID retained for diagnosis; no snapshot created." >&2
exit 1
