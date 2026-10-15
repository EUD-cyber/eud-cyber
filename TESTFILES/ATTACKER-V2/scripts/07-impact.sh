#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 07 - Impact / Ransomware Simulation
#
# Input:
#   state/compromised-hosts.json
#
# Purpose:
#   Generate controlled ransomware/impact indicators on hosts
#   successfully compromised during Phase 03.
#
# IMPORTANT:
#   Only synthetic files created by this script are affected.
#   Existing user/system files are never encrypted/deleted.
# ============================================================


# ============================================================
# PATHS / CONFIG
# ============================================================

BASE_DIR="/opt/nordic-attack"
CONFIG_FILE="$BASE_DIR/config/defaults.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p \
    "$NORDIC_LOG_DIR" \
    "$NORDIC_STATE_DIR"


# ============================================================
# CAMPAIGN CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"

COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

IMPACT_STATE="$NORDIC_STATE_DIR/impact.json"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-07-impact.log"


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

    printf '%s INCIDENT=%s PHASE=07 %s\n' \
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

if [[ ! -f "$COMPROMISED_STATE" ]]; then

    echo "[ERROR] Missing compromised host inventory:"
    echo "$COMPROMISED_STATE"
    echo
    echo "Run Phase 03 first."

    exit 1
fi


if [[ -z "$SSH_PASSWORD" ]]; then

    echo "[ERROR] Campaign SSH password is missing."
    exit 1
fi


# ============================================================
# LOAD COMPROMISED HOSTS
#
# Format:
#
# IP|SSH_PORT|SSH_USER
# ============================================================

mapfile -t COMPROMISED < <(
    python3 - "$COMPROMISED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):

    if not host.get("compromised"):
        continue

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
echo " PHASE 07 - IMPACT / RANSOMWARE SIMULATION"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Compromised hosts: ${#COMPROMISED[@]}"

echo


# ============================================================
# EMPTY CAMPAIGN
# ============================================================

if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."

    python3 - "$IMPACT_STATE" "$INCIDENT_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone

data = {
    "incident_id": sys.argv[2],
    "generated": datetime.now(timezone.utc).isoformat(),
    "count": 0,
    "hosts": [],
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY

    ground_truth "PHASE_COMPLETE impacted_hosts=0"

    exit 0
fi


# ============================================================
# TEMP RESULT FILE
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.impact.tmp"

: > "$TMP_RESULTS"

SUCCESS_COUNT=0
FAILED_COUNT=0


# ============================================================
# IMPACT SIMULATION
# ============================================================

for RECORD in "${COMPROMISED[@]}"; do

    IFS='|' read -r HOST SSH_PORT SSH_USER <<< "$RECORD"

    echo
    echo "------------------------------------------------------------"
    echo " Compromised host: $HOST"
    echo "------------------------------------------------------------"
    echo

    log "[*] Starting impact simulation on $HOST"

    ground_truth \
        "IMPACT_START host=$HOST"


    # ========================================================
    # REMOTE SCRIPT
    #
    # Creates a completely isolated synthetic file tree:
    #
    # /tmp/nordic-impact-<incident>/
    #
    # Nothing outside this directory is modified.
    # ========================================================

    REMOTE_RESULT="$(
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
            bash -s -- "$INCIDENT_ID" <<'REMOTE'
set -e

INCIDENT_ID="$1"

IMPACT_DIR="/tmp/nordic-impact-${INCIDENT_ID}"

DATA_DIR="$IMPACT_DIR/company-data"

mkdir -p \
    "$DATA_DIR/Finance" \
    "$DATA_DIR/HR" \
    "$DATA_DIR/Production" \
    "$DATA_DIR/Webshop" \
    "$DATA_DIR/Management"


# ------------------------------------------------------------
# Generate synthetic company files
# ------------------------------------------------------------

cat > "$DATA_DIR/Finance/invoices.csv" <<EOF
Invoice,Customer,Amount
INV-2026-1001,Nordic Customer 01,12500
INV-2026-1002,Nordic Customer 02,8700
INV-2026-1003,Nordic Customer 03,19300
EOF


cat > "$DATA_DIR/HR/employees.csv" <<EOF
EmployeeID,Department,Status
EMP-1001,Production,Active
EMP-1002,IT,Active
EMP-1003,Sales,Active
EOF


cat > "$DATA_DIR/Production/production-plan.txt" <<EOF
Nordic Manufacturing
Production Schedule

Line 1: Running
Line 2: Running
Line 3: Maintenance scheduled
EOF


cat > "$DATA_DIR/Webshop/orders.csv" <<EOF
OrderID,Status
ORD-5001,Processing
ORD-5002,Ready
ORD-5003,Processing
EOF


cat > "$DATA_DIR/Management/business-plan.txt" <<EOF
NORDIC MANUFACTURING A/S

CONFIDENTIAL

Synthetic H3 CyberLab training document.
EOF


# Additional dummy documents

for NUMBER in $(seq 1 10); do

    printf \
        "Nordic Manufacturing synthetic training document %s\n" \
        "$NUMBER" \
        > "$DATA_DIR/Management/document-${NUMBER}.txt"

done


# ------------------------------------------------------------
# Count files before impact
# ------------------------------------------------------------

BEFORE="$(
    find "$DATA_DIR" \
        -type f \
        | wc -l
)"


# ------------------------------------------------------------
# Simulated ransomware impact
#
# Rename ONLY the files created above.
#
# Example:
#
# invoices.csv
#
# becomes
#
# invoices.csv.locked
#
# ------------------------------------------------------------

while IFS= read -r -d '' FILE; do

    mv -- "$FILE" "${FILE}.locked"

done < <(
    find "$DATA_DIR" \
        -type f \
        -print0
)


# ------------------------------------------------------------
# Create ransomware note
# ------------------------------------------------------------

cat > "$IMPACT_DIR/README_RECOVER_FILES.txt" <<EOF
============================================================
YOUR FILES ARE UNAVAILABLE
============================================================

Nordic Manufacturing A/S
H3 CyberLab Incident Simulation

Incident:
$INCIDENT_ID

Multiple company files are currently unavailable.

This is a CONTROLLED TRAINING SIMULATION.

No real encryption has been performed.
No real user data has been modified.

Contact the Incident Response Team.

============================================================
EOF


# ------------------------------------------------------------
# Count impacted files
# ------------------------------------------------------------

LOCKED="$(
    find "$DATA_DIR" \
        -type f \
        -name "*.locked" \
        | wc -l
)"


HOSTNAME_VALUE="$(
    hostname 2>/dev/null ||
    echo unknown
)"


printf \
    "NORDIC_IMPACT_OK|%s|%s|%s|%s\n" \
    "$IMPACT_DIR" \
    "$BEFORE" \
    "$LOCKED" \
    "$HOSTNAME_VALUE"
REMOTE
    )"

    SSH_RESULT=$?


    # ========================================================
    # SUCCESS
    # ========================================================

    if [[ $SSH_RESULT -eq 0 ]] &&
       grep -q '^NORDIC_IMPACT_OK|' <<< "$REMOTE_RESULT"; then

        RESULT_LINE="$(
            printf '%s\n' "$REMOTE_RESULT" |
            grep '^NORDIC_IMPACT_OK|' |
            tail -n 1
        )"

        IFS='|' read -r \
            STATUS \
            IMPACT_DIR \
            ORIGINAL_FILES \
            LOCKED_FILES \
            HOSTNAME_VALUE \
            <<< "$RESULT_LINE"


        SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))


        log "[+] Impact simulation completed on $HOST"
        log "    Hostname: $HOSTNAME_VALUE"
        log "    Impact directory: $IMPACT_DIR"
        log "    Files affected: $LOCKED_FILES"


        printf '%s|%s|%s|%s|%s\n' \
            "$HOST" \
            "$HOSTNAME_VALUE" \
            "$IMPACT_DIR" \
            "$ORIGINAL_FILES" \
            "$LOCKED_FILES" \
            >> "$TMP_RESULTS"


        ground_truth \
            "IMPACT_SUCCESS host=$HOST hostname=$HOSTNAME_VALUE files=$LOCKED_FILES directory=$IMPACT_DIR"

    else

        FAILED_COUNT=$(( FAILED_COUNT + 1 ))

        log "[WARNING] Impact simulation failed on $HOST"

        ground_truth \
            "IMPACT_FAILED host=$HOST"

    fi

done


# ============================================================
# CREATE impact.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$IMPACT_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone

source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]

hosts = []

with open(source_file, encoding="utf-8") as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue

        (
            ip,
            hostname,
            impact_dir,
            original_files,
            locked_files,
        ) = line.split("|", 4)

        hosts.append(
            {
                "ip": ip,
                "hostname": hostname,
                "impacted": True,
                "impact_type": "ransomware-simulation",
                "directory": impact_dir,
                "original_files": int(original_files),
                "locked_files": int(locked_files),
                "real_encryption": False,
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
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 07 COMPLETED"
echo "============================================================"
echo

echo "Compromised hosts:"
echo "  ${#COMPROMISED[@]}"

echo

echo "Hosts impacted:"
echo "  $SUCCESS_COUNT"

echo

echo "Failed:"
echo "  $FAILED_COUNT"

echo

echo "Impact inventory:"
echo "  $IMPACT_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE impacted=$SUCCESS_COUNT failed=$FAILED_COUNT"


exit 0