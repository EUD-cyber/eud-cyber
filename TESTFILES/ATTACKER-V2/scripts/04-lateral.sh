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
#   Generate visible east-west discovery activity from
#   compromised hosts inside the CyberLab.
#
# Activity:
#   - ICMP discovery
#   - TCP probes against common internal services
#
# Ports:
#   22   SSH
#   80   HTTP
#   443  HTTPS
#   445  SMB
#   3389 RDP
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

PROBE_PORTS="22 80 443 445 3389"


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

    # Support both names if older state files exist
    user = host.get("ssh_user") or host.get("ssh_username") or "ubuntu"

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
log "[*] Probe ports: $PROBE_PORTS"

echo


if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."
    log "[*] Phase 04 has nothing to execute."

    ground_truth "PHASE_COMPLETE sources=0 relationships=0"

    exit 0
fi


# ============================================================
# INTERNAL DISCOVERY
# ============================================================

TOTAL_RELATIONSHIPS=0
SUCCESSFUL_SOURCES=0
FAILED_SOURCES=0


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
    # Build target array
    # --------------------------------------------------------

    REMOTE_TARGETS=()

    for TARGET in "${TARGETS[@]}"; do

        # Never probe the source host itself
        if [[ "$TARGET" == "$SOURCE" ]]; then
            continue
        fi

        REMOTE_TARGETS+=("$TARGET")
    done


    if [[ ${#REMOTE_TARGETS[@]} -eq 0 ]]; then

        log "[*] No additional targets for $SOURCE"

        continue
    fi


    log "[*] Starting internal discovery from $SOURCE"
    log "[*] Targets from $SOURCE: ${#REMOTE_TARGETS[@]}"


    # --------------------------------------------------------
    # Remote discovery script
    #
    # Every target is passed as its own positional argument.
    # --------------------------------------------------------

    read -r -d '' REMOTE_SCRIPT <<'REMOTE_EOF' || true

PORTS="22 80 443 445 3389"

for TARGET in "$@"; do

    echo "[DISCOVERY] target=$TARGET"

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    if ping -c 1 -W 1 "$TARGET" >/dev/null 2>&1; then

        echo "[PING] target=$TARGET status=reachable"

    else

        echo "[PING] target=$TARGET status=no-reply"

    fi


    # --------------------------------------------------------
    # TCP service probes
    # --------------------------------------------------------

    for PORT in $PORTS; do

        if timeout 1 bash -c \
            "echo >/dev/tcp/$TARGET/$PORT" \
            >/dev/null 2>&1
        then

            echo "[TCP] target=$TARGET port=$PORT status=open"

        else

            echo "[TCP] target=$TARGET port=$PORT status=closed"

        fi

    done

done

REMOTE_EOF


    # --------------------------------------------------------
    # Execute FROM compromised host
    # --------------------------------------------------------

    REMOTE_OUTPUT="$(
        sshpass -p "$SSH_PASSWORD" \
            ssh \
                -p "$SSH_PORT" \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
                -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no \
                "$SSH_USER@$SOURCE" \
                bash -s -- "${REMOTE_TARGETS[@]}" \
                <<< "$REMOTE_SCRIPT" \
                2>&1
    )"

    RESULT=$?


    # --------------------------------------------------------
    # Display + log remote output
    # --------------------------------------------------------

    while IFS= read -r LINE; do

        [[ -z "$LINE" ]] && continue

        log "[$SOURCE] $LINE"

    done <<< "$REMOTE_OUTPUT"


    # --------------------------------------------------------
    # SSH failure
    # --------------------------------------------------------

    if [[ $RESULT -ne 0 ]]; then

        FAILED_SOURCES=$(( FAILED_SOURCES + 1 ))

        log "[WARNING] Internal discovery failed from $SOURCE"

        ground_truth \
            "INTERNAL_DISCOVERY_FAILED source=$SOURCE"

        continue
    fi


    SUCCESSFUL_SOURCES=$(( SUCCESSFUL_SOURCES + 1 ))


    # --------------------------------------------------------
    # Ground truth
    # --------------------------------------------------------

    for TARGET in "${REMOTE_TARGETS[@]}"; do

        TOTAL_RELATIONSHIPS=$(( TOTAL_RELATIONSHIPS + 1 ))

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

echo "Successful source hosts:"
echo "  $SUCCESSFUL_SOURCES"

echo

echo "Failed source hosts:"
echo "  $FAILED_SOURCES"

echo

echo "Discovered internal hosts:"
echo "  ${#TARGETS[@]}"

echo

echo "Source → target relationships:"
echo "  $TOTAL_RELATIONSHIPS"

echo

echo "Probe ports:"
echo "  $PROBE_PORTS"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE sources=${#COMPROMISED[@]} successful_sources=$SUCCESSFUL_SOURCES failed_sources=$FAILED_SOURCES relationships=$TOTAL_RELATIONSHIPS"


exit 0