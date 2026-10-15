#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 04 - Internal Discovery / Lateral Activity
#
# Source:
#   Hosts successfully compromised in Phase 03
#
# Targets:
#   Other hosts discovered in Phase 01
#
# Purpose:
#   Generate realistic east-west discovery activity from
#   compromised hosts inside the CyberLab.
# ============================================================


BASE_DIR="/opt/nordic-attack"
CONFIG_FILE="$BASE_DIR/config/defaults.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p "$NORDIC_LOG_DIR" "$NORDIC_STATE_DIR"


# ============================================================
# CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"

DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"
COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-04-lateral.log"


# ============================================================
# FUNCTIONS
# ============================================================

log() {
    local MESSAGE="$1"

    echo "$MESSAGE"

    printf '%s %s\n' \
        "$(date --iso-8601=seconds)" \
        "$MESSAGE" \
        >> "$LOG_FILE"
}


ground_truth() {
    local MESSAGE="$1"

    printf '%s INCIDENT=%s PHASE=04 %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


# ============================================================
# REQUIRED COMMANDS
# ============================================================

for CMD in python3 sshpass ssh; do

    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[ERROR] Required command not found: $CMD"
        exit 1
    fi

done


# ============================================================
# VALIDATION
# ============================================================

if [[ ! -f "$DISCOVERED_STATE" ]]; then
    echo "[ERROR] Missing discovered host inventory."
    echo "Run Phase 01 first."
    exit 1
fi

if [[ ! -f "$COMPROMISED_STATE" ]]; then
    echo "[ERROR] Missing compromised host inventory."
    echo "Run Phase 03 first."
    exit 1
fi

if [[ -z "$SSH_PASSWORD" ]]; then
    echo "[ERROR] Campaign SSH password is missing."
    exit 1
fi


# ============================================================
# LOAD TARGETS
# ============================================================

mapfile -t TARGETS < <(
    python3 - "$DISCOVERED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):
    ip = host.get("ip")
    if ip:
        print(ip)
PY
)


# ============================================================
# LOAD COMPROMISED HOSTS
#
# Format:
#
# IP|PORT|USER
# ============================================================

mapfile -t COMPROMISED < <(
    python3 - "$COMPROMISED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):
    ip = host.get("ip")
    port = host.get("ssh_port", 22)
    user = host.get("ssh_user", "ubuntu")

    if ip:
        print(f"{ip}|{port}|{user}")
PY
)


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 04 - INTERNAL DISCOVERY"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Compromised source hosts: ${#COMPROMISED[@]}"
log "[*] Discovered internal targets: ${#TARGETS[@]}"

echo


if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."
    log "[*] Phase 04 has nothing to execute."

    ground_truth "PHASE_COMPLETE sources=0"

    exit 0
fi


# ============================================================
# INTERNAL DISCOVERY
# ============================================================

TOTAL_PROBES=0

for SOURCE_RECORD in "${COMPROMISED[@]}"; do

    IFS='|' read -r SOURCE SSH_PORT SSH_USER <<< "$SOURCE_RECORD"

    echo
    echo "############################################################"
    echo " COMPROMISED SOURCE: $SOURCE"
    echo "############################################################"
    echo

    ground_truth \
        "INTERNAL_DISCOVERY_START source=$SOURCE"


    # --------------------------------------------------------
    # Build target list for remote host
    #
    # Do not probe itself.
    # --------------------------------------------------------

    REMOTE_TARGETS=""

    for TARGET in "${TARGETS[@]}"; do

        if [[ "$TARGET" == "$SOURCE" ]]; then
            continue
        fi

        REMOTE_TARGETS+="$TARGET "
    done


    if [[ -z "$REMOTE_TARGETS" ]]; then
        log "[*] No additional targets for $SOURCE"
        continue
    fi


    # --------------------------------------------------------
    # Execute discovery FROM compromised host
    #
    # Generates:
    #
    # - ICMP activity
    # - TCP connection attempts against common internal
    #   administration/service ports
    #
    # Ports:
    #
    # 22   SSH
    # 80   HTTP
    # 443  HTTPS
    # 445  SMB
    # 3389 RDP
    #
    # --------------------------------------------------------

    REMOTE_SCRIPT='
TARGETS="$1"

for TARGET in $TARGETS; do

    echo "[DISCOVERY] $TARGET"

    ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1 || true

    for PORT in 22 80 443 445 3389; do

        timeout 1 bash -c \
            "echo >/dev/tcp/$TARGET/$PORT" \
            >/dev/null 2>&1 || true

    done

done
'


    log "[*] Starting internal discovery from $SOURCE"


    sshpass -p "$SSH_PASSWORD" \
        ssh \
            -p "$SSH_PORT" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            "$SSH_USER@$SOURCE" \
            bash -s -- "$REMOTE_TARGETS" \
            <<< "$REMOTE_SCRIPT"


    RESULT=$?


    if [[ $RESULT -ne 0 ]]; then

        log "[WARNING] Internal discovery failed from $SOURCE"

        ground_truth \
            "INTERNAL_DISCOVERY_FAILED source=$SOURCE"

        continue

    fi


    # --------------------------------------------------------
    # Ground truth
    # --------------------------------------------------------

    for TARGET in "${TARGETS[@]}"; do

        if [[ "$TARGET" == "$SOURCE" ]]; then
            continue
        fi

        TOTAL_PROBES=$(( TOTAL_PROBES + 1 ))

        ground_truth \
            "INTERNAL_DISCOVERY source=$SOURCE target=$TARGET"

    done


    log "[+] Internal discovery completed from $SOURCE"

done


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 04 COMPLETED"
echo "============================================================"
echo

echo "Compromised source hosts:"
echo "  ${#COMPROMISED[@]}"

echo

echo "Discovered internal hosts:"
echo "  ${#TARGETS[@]}"

echo

echo "Source → target relationships:"
echo "  $TOTAL_PROBES"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE sources=${#COMPROMISED[@]} relationships=$TOTAL_PROBES"


exit 0