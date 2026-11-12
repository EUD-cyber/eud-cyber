#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# CyberLab deployment phase; the caller owns profile/component selection.
# Usage: bash deploy.sh Big|Mini [lab-count] [Big component ...]
# Examples:
#   bash deploy.sh Big 1
#   bash deploy.sh Big 2 WAZUH MRNOBODY
#   bash deploy.sh Mini 2
# Image/storage/network and VM_CPU/VM_MEM/VM_HDD settings come from install.sh.
# Example override: APPSRV01_CPU=2 APPSRV01_MEM=2048 APPSRV01_HDD=32G
# Direct Mini calls must supply their hardware overrides; profile defaults live
# in install.sh. Unset overrides use the shared VM installers\' original defaults.
# This file does not replace or modify install.sh or the individual VM scripts.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$SCRIPT_DIR"

die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
log() { printf '[+] %s\n' "$*"; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    printf 'Usage: bash deploy.sh Big|Mini [1-16] [Big component ...]\n'
    printf 'Big components: VULNSRV02 KALI02 APPSRV01 CLIENT01 WAZUH TPOT MRNOBODY\n'
    printf 'Example: bash deploy.sh Big 2 WAZUH MRNOBODY\n'
    exit 0
fi

SPEC="${1:-${SPEC:-}}"
LABCOUNT="${2:-${LABCOUNT:-1}}"
case "$SPEC" in
    Big|Mini) ;;
    *) die "Profile must be Big or Mini. See: bash deploy.sh --help" ;;
esac
[[ "$LABCOUNT" =~ ^([1-9]|1[0-6])$ ]] || die "Lab count must be between 1 and 16."
export SPEC LABCOUNT

OPNSENSE="OPNSENSE/OPNSENSE_installer.sh"
GUAC_CONFIG="GUACVM/GUACVM_ip.sh"
VM_SCRIPTS=()

if [[ "$SPEC" == "Big" ]]; then
    VM_SCRIPTS=("GUACVM/GUACVM_installer.sh"
                "KALI01/KALI01_installer.sh"
                "VULNSRV01/VULNSRV01_installer.sh")
    declare -A selected=()
    for component in "${@:3}"; do
        # Accept individual quoted tags returned by whiptail as well.
        component="${component//\"/}"
        [[ -n "$component" ]] || die "Empty optional component."
        [[ -z "${selected[$component]:-}" ]] || continue
        case "$component" in
            VULNSRV02|KALI02|APPSRV01|CLIENT01|WAZUH)
                VM_SCRIPTS+=("${component}/${component}_installer.sh") ;;
            TPOT) VM_SCRIPTS+=("TPOT01/TPOT01_installer.sh") ;;
            MRNOBODY) VM_SCRIPTS+=("MRNOBODY/mrnobody_installer.sh") ;;
            *) die "Unknown Big component: $component" ;;
        esac
        selected[$component]=1
    done
else
    (( $# <= 2 )) || die "Mini uses a fixed VM selection; optional components are only supported for Big."
    # Both profiles use the same lab-aware VM installers. Only selection and
    # hardware overrides from install.sh differ.
    VM_SCRIPTS=("GUACVM/GUACVM_installer.sh"
                "CLIENT01/CLIENT01_installer.sh"
                "VULNSRV01/VULNSRV01_installer.sh"
                "VULNSRV02/VULNSRV02_installer.sh"
                "KALI01/KALI01_installer.sh"
                "WAZUH/WAZUH_installer.sh"
                "APPSRV01/APPSRV01_installer.sh")
fi

# Validate per-VM hardware overrides before any configuration or host setup.
# HDD retains each VM installer's existing resize semantics (+SIZE).
RESOURCE_KEYS=(OPNSENSE GUACVM KALI01 KALI02 VULNSRV01 VULNSRV02
               APPSRV01 CLIENT01 WAZUH TPOT01 MRNOBODY)
HARDWARE_SETTINGS=()
for resource_key in "${RESOURCE_KEYS[@]}"; do
    for resource_type in CPU MEM HDD; do
        setting="${resource_key}_${resource_type}"
        HARDWARE_SETTINGS+=("$setting")
        if [[ -v "$setting" ]]; then
            value="${!setting}"
            if [[ "$resource_type" == "HDD" ]]; then
                [[ "$value" =~ ^[1-9][0-9]*[GMT]$ ]] ||
                    die "$setting must be a positive size such as 32G."
            else
                [[ "$value" =~ ^[1-9][0-9]*$ ]] ||
                    die "$setting must be a positive integer (MEM is in MB)."
            fi
            export "$setting"
        fi
    done
done

# Validate the complete plan before writing logs/configuration or running setup.
missing=()
for script in repo.sh pre_req.sh open-vswitch-pre.sh open-vswitch.sh \
    open-vswitch-last.sh OPNSENSE/generate_config.sh "$GUAC_CONFIG" \
    "$OPNSENSE" "${VM_SCRIPTS[@]}"; do
    [[ -f "$script" && -s "$script" ]] || missing+=("$script")
done
if (( ${#missing[@]} )); then
    printf '[ERROR] Required deployment files are missing or empty:\n' >&2
    printf '  %s\n' "${missing[@]}" >&2
    die "Deployment stopped before making changes. Restore the required lab-aware scripts first."
fi
[[ "$EUID" -eq 0 ]] || die "Run as root on the Proxmox host."
for command_name in bash python3 pvesh tmux tee; do
    require_command "$command_name"
done
SESSION="deploy-all"
if tmux has-session -t "$SESSION" 2>/dev/null; then
    die "tmux session '$SESSION' already exists. Attach with: tmux attach -t $SESSION"
fi

# Keep the cluster-wide existing-lab check used by install.sh.
inventory="$(pvesh get /cluster/resources --type vm --output-format json)" ||
    die "Cannot check existing VMs; deployment stopped."
python3 - "$LABCOUNT" "$inventory" <<'PY'
import json
import re
import sys

count = int(sys.argv[1])
resources = json.loads(sys.argv[2])
if not isinstance(resources, list):
    raise SystemExit("Invalid VM inventory; deployment stopped.")
conflicts = []
for vm in resources:
    name = str(vm.get("name", ""))
    match = re.match(r"^lab(\d+)[-_]", name, re.IGNORECASE)
    if match and 1 <= int(match.group(1)) <= count:
        conflicts.append(f"{vm.get('vmid', '?')}: {name}")
if conflicts:
    raise SystemExit(
        "Existing VMs/containers found in the selected labs:\n"
        + "\n".join(conflicts)
        + "\nDeployment stopped. No existing VMs will be replaced."
    )
PY

mkdir -p LOGS
exec > >(tee -a deploy.log) 2>&1
trap 'result=$?; printf "[ERROR] Deployment failed at line %s (exit %s). See deploy.log.\n" "$LINENO" "$result" >&2; exit "$result"' ERR

log "Preparing $SPEC deployment: $LABCOUNT lab(s)."
for ((lab = 1; lab <= LABCOUNT; lab++)); do
    log "Configuring OPNsense and Guacamole for lab$lab."
    bash OPNSENSE/generate_config.sh "$lab"
    bash "$GUAC_CONFIG" "$lab"
done

log "Preparing repository, packages and Open vSwitch."
bash repo.sh
bash pre_req.sh
bash open-vswitch-pre.sh
for ((lab = 1; lab <= LABCOUNT; lab++)); do
    bash open-vswitch.sh "$lab"
done
bash open-vswitch-last.sh

# Finish every OPNsense installer in the foreground before starting other VMs.
for ((lab = 1; lab <= LABCOUNT; lab++)); do
    log "Installing OPNsense for lab$lab."
    bash "$OPNSENSE" "$lab"
done

# Build one sequential worker. Quote paths/arguments rather than interpolating
# user choices into executable shell text. All paths resolve from SCRIPT_DIR.
printf -v worker 'set -Eeuo pipefail\ncd -- %q\nexec > >(tee -a deploy.log) 2>&1\n' "$SCRIPT_DIR"
worker+=$'trap \'result=$?; if (( result == 0 )); then echo "[+] CyberLab deployment completed."; else echo "[ERROR] Background deployment failed (exit $result). See deploy.log." >&2; fi\' EXIT\n'
for ((lab = 1; lab <= LABCOUNT; lab++)); do
    for script in "${VM_SCRIPTS[@]}"; do
        printf -v worker '%sprintf %q\nbash %q %q\n' "$worker" \
            "[+] lab${lab}: ${script}\\n" "$SCRIPT_DIR/$script" "$lab"
    done
done

# An existing tmux server may retain old environment values. Pass the settings
# selected by install.sh explicitly, clearing stale values when they are unset.
settings=(SPEC LABCOUNT LINUX_IMG KALI_IMG WAZUH_IMG OPNSENSE_IMG_URL
          OPNSENSE_VERSION LOCAL LVM BRIDGE "${HARDWARE_SETTINGS[@]}")
worker_env=(env)
for setting in "${settings[@]}"; do
    worker_env+=(-u "$setting")
done
for setting in "${settings[@]}"; do
    if [[ -v "$setting" ]]; then
        worker_env+=("$setting=${!setting}")
    fi
done
tmux new-session -d -s "$SESSION" "${worker_env[@]}" bash -c "$worker"

log "Remaining VM installations started in tmux ($SPEC, $LABCOUNT lab(s))."
log "Attach: tmux attach -t $SESSION"
log "Follow the log: tail -f $SCRIPT_DIR/deploy.log"

