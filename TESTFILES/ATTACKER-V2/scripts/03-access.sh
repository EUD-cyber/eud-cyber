#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 03 - Initial Access / SSH
#
# Input:
#   state/discovered-hosts.json
#
# GUI / environment:
#   NORDIC_SSH_USER
#   NORDIC_SSH_PASSWORD
#   NORDIC_SSH_PORT      optional
#
# Output:
#   state/compromised-hosts.json
#
# A host is only marked compromised when SSH authentication
# with the supplied campaign credentials succeeds.
# ============================================================


# ============================================================
# PATHS / CONFIG
# ============================================================

BASE_DIR="/opt/nordic-attack"
CONFIG_FILE="$BASE_DIR/config/defaults.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found:"
    echo "$CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p \
    "$NORDIC_STATE_DIR" \
    "$NORDIC_LOG_DIR"


# ============================================================
# CAMPAIGN CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

SSH_USER="${NORDIC_SSH_USER:-$NORDIC_DEFAULT_SSH_USER}"
SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"
SSH_PORT="${NORDIC_SSH_PORT:-$NORDIC_DEFAULT_SSH_PORT}"

DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"
COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-03-access.log"


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

    printf '%s INCIDENT=%s PHASE=03 %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


valid_port() {

    local PORT="$1"

    [[ "$PORT" =~ ^[0-9]+$ ]] || return 1

    (( PORT >= 1 && PORT <= 65535 ))
}


# ============================================================
# REQUIRED COMMANDS
# ============================================================

for CMD in python3 timeout sshpass ssh; do

    if ! command -v "$CMD" >/dev/null 2>&1; then

        echo "[ERROR] Required command not found: $CMD"

        if [[ "$CMD" == "sshpass" ]]; then
            echo
            echo "Package required:"
            echo "  sshpass"
        fi

        exit 1

    fi

done


# ============================================================
# VALIDATION
# ============================================================

if [[ ! -f "$DISCOVERED_STATE" ]]; then

    echo "[ERROR] Phase 01 inventory not found:"
    echo "$DISCOVERED_STATE"
    echo
    echo "Run Phase 01 first."

    exit 1
fi


if [[ -z "$SSH_USER" ]]; then

    echo "[ERROR] SSH username is missing."
    exit 1

fi


if [[ -z "$SSH_PASSWORD" ]]; then

    echo "[ERROR] SSH password is missing."
    echo
    echo "Supply the campaign password through the GUI."

    exit 1

fi


if ! valid_port "$SSH_PORT"; then

    echo "[ERROR] Invalid SSH port:"
    echo "$SSH_PORT"

    exit 1

fi


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 03 - INITIAL ACCESS"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] SSH username: $SSH_USER"
log "[*] SSH port: $SSH_PORT"

# Deliberately NEVER log the password.

echo


# ============================================================
# LOAD DISCOVERED HOSTS
# ============================================================

mapfile -t HOSTS < <(
    python3 - "$DISCOVERED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):
    ip = host.get("ip")

    if ip:
        print(ip)
PY
)


log "[*] Hosts supplied by Phase 01: ${#HOSTS[@]}"

echo


# ============================================================
# TEMPORARY RESULTS
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.compromised-hosts.tmp"

: > "$TMP_RESULTS"

SSH_FOUND=0
LOGIN_SUCCESS=0
LOGIN_FAILED=0


# ============================================================
# SSH DISCOVERY + AUTHENTICATION
# ============================================================

for HOST in "${HOSTS[@]}"; do

    echo
    echo "------------------------------------------------------------"
    echo " Host: $HOST"
    echo "------------------------------------------------------------"
    echo


    # --------------------------------------------------------
    # Check TCP/SSH port
    # --------------------------------------------------------

    if ! timeout "$NORDIC_CONNECT_TIMEOUT" \
        bash -c "echo >/dev/tcp/$HOST/$SSH_PORT" \
        >/dev/null 2>&1; then

        log "[-] SSH port closed/unreachable: $HOST:$SSH_PORT"
        continue

    fi


    SSH_FOUND=$(( SSH_FOUND + 1 ))

    log "[+] SSH candidate: $HOST:$SSH_PORT"

    ground_truth \
        "SSH_DISCOVERED ip=$HOST port=$SSH_PORT"


    # --------------------------------------------------------
    # Attempt supplied credentials
    #
    # Important:
    # - one configured username
    # - one configured password
    # - no brute forcing
    # - no credential lists
    # --------------------------------------------------------

    SSH_OUTPUT="$(
        sshpass -p "$SSH_PASSWORD" \
        ssh \
            -p "$SSH_PORT" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 \
            "$SSH_USER@$HOST" \
            'printf "NORDIC_ACCESS_OK\n"; uname -s 2>/dev/null || true; hostname 2>/dev/null || true' \
            2>/dev/null
    )"

    RESULT=$?


    # --------------------------------------------------------
    # Authentication successful
    # --------------------------------------------------------

    if [[ $RESULT -eq 0 ]] &&
       grep -q '^NORDIC_ACCESS_OK$' <<< "$SSH_OUTPUT"; then

        LOGIN_SUCCESS=$(( LOGIN_SUCCESS + 1 ))

        OS="$(
            printf '%s\n' "$SSH_OUTPUT" |
            sed -n '2p'
        )"

        HOSTNAME="$(
            printf '%s\n' "$SSH_OUTPUT" |
            sed -n '3p'
        )"


        log "[COMPROMISED] $HOST"

        if [[ -n "$HOSTNAME" ]]; then
            log "              Hostname: $HOSTNAME"
        fi

        if [[ -n "$OS" ]]; then
            log "              OS: $OS"
        fi


        printf '%s|%s|%s|%s|%s\n' \
            "$HOST" \
            "$SSH_PORT" \
            "$SSH_USER" \
            "$HOSTNAME" \
            "$OS" \
            >> "$TMP_RESULTS"


        ground_truth \
            "ACCESS_SUCCESS ip=$HOST port=$SSH_PORT user=$SSH_USER hostname=$HOSTNAME os=$OS"

    else

        LOGIN_FAILED=$(( LOGIN_FAILED + 1 ))

        log "[FAILED] SSH authentication failed: $HOST"

        ground_truth \
            "ACCESS_FAILED ip=$HOST port=$SSH_PORT user=$SSH_USER"

    fi

done


# ============================================================
# CREATE compromised-hosts.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$COMPROMISED_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone

source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]

hosts = []

with open(source_file, "r", encoding="utf-8") as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue

        ip, port, user, hostname, os_name = line.split("|", 4)

        hosts.append(
            {
                "ip": ip,
                "ssh_port": int(port),
                "ssh_user": user,
                "hostname": hostname,
                "os": os_name,
                "access": "ssh",
                "authenticated": True,
                "compromised": True,
            }
        )


data = {
    "incident_id": incident_id,
    "generated": datetime.now(timezone.utc).isoformat(),
    "count": len(hosts),
    "hosts": hosts,
}


with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


rm -f "$TMP_RESULTS"


# ============================================================
# UPDATE CENTRAL INVENTORY
# ============================================================

python3 - \
    "$DISCOVERED_STATE" \
    "$COMPROMISED_STATE" \
    "$SSH_PORT" <<'PY'

import json
import sys

inventory_file = sys.argv[1]
compromised_file = sys.argv[2]
ssh_port = int(sys.argv[3])


with open(inventory_file, "r", encoding="utf-8") as f:
    inventory = json.load(f)


with open(compromised_file, "r", encoding="utf-8") as f:
    compromised = json.load(f)


compromised_by_ip = {
    host["ip"]: host
    for host in compromised.get("hosts", [])
}


for host in inventory.get("hosts", []):

    ip = host.get("ip")

    services = host.setdefault(
        "services",
        {}
    )

    if ip in compromised_by_ip:

        result = compromised_by_ip[ip]

        host["ssh_candidate"] = True
        host["compromised"] = True
        host["status"] = "compromised"

        services["ssh"] = {
            "port": ssh_port,
            "authenticated": True,
            "user": result.get("ssh_user", ""),
        }

        host["hostname"] = result.get(
            "hostname",
            ""
        )

        host["os"] = result.get(
            "os",
            ""
        )

    else:

        # Do not mark every non-compromised host as an SSH
        # candidate. A later enhancement can store failed SSH
        # candidates separately if required.

        host.setdefault(
            "compromised",
            False
        )


with open(inventory_file, "w", encoding="utf-8") as f:
    json.dump(inventory, f, indent=2)

PY


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 03 COMPLETED"
echo "============================================================"
echo

echo "Discovered hosts checked:"
echo "  ${#HOSTS[@]}"

echo

echo "SSH services found:"
echo "  $SSH_FOUND"

echo

echo "Successful SSH access:"
echo "  $LOGIN_SUCCESS"

echo

echo "Failed SSH authentication:"
echo "  $LOGIN_FAILED"

echo

echo "Compromised host inventory:"
echo "  $COMPROMISED_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE ssh_found=$SSH_FOUND compromised=$LOGIN_SUCCESS failed=$LOGIN_FAILED"


exit 0