#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 05 - Data Staging
#
# Input:
#   state/compromised-hosts.json
#
# Purpose:
#   Create controlled synthetic staging data on hosts that
#   were successfully compromised during Phase 03.
#
# No real user/business data is collected.
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

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-05-staging.log"

STAGING_STATE="$NORDIC_STATE_DIR/staged-data.json"


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

    printf '%s INCIDENT=%s PHASE=05 %s\n' \
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
echo " PHASE 05 - DATA STAGING"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Compromised hosts: ${#COMPROMISED[@]}"

echo


# ============================================================
# NO COMPROMISED HOSTS
# ============================================================

if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."
    log "[*] Phase 05 has nothing to stage."

    python3 - "$STAGING_STATE" "$INCIDENT_ID" <<'PY'
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

    ground_truth "PHASE_COMPLETE staged_hosts=0"

    exit 0
fi


# ============================================================
# TEMP RESULT FILE
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.staging.tmp"

: > "$TMP_RESULTS"

STAGED_COUNT=0
FAILED_COUNT=0


# ============================================================
# STAGE DATA
# ============================================================

for RECORD in "${COMPROMISED[@]}"; do

    IFS='|' read -r HOST SSH_PORT SSH_USER <<< "$RECORD"

    echo
    echo "------------------------------------------------------------"
    echo " Compromised host: $HOST"
    echo "------------------------------------------------------------"
    echo

    log "[*] Starting staging on $HOST"

    ground_truth \
        "STAGING_START host=$HOST user=$SSH_USER"


    # --------------------------------------------------------
    # Remote staging directory
    #
    # Everything stays under /tmp and contains only
    # synthetic campaign data.
    # --------------------------------------------------------

    REMOTE_DIR="/tmp/.nordic-${INCIDENT_ID}"
    REMOTE_FILE="${REMOTE_DIR}/nordic-data-${INCIDENT_ID}.txt"


    # --------------------------------------------------------
    # Create synthetic data
    # --------------------------------------------------------

    REMOTE_SCRIPT='
set -e

INCIDENT_ID="$1"
REMOTE_DIR="$2"
REMOTE_FILE="$3"

mkdir -p "$REMOTE_DIR"

chmod 700 "$REMOTE_DIR"

HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"

cat > "$REMOTE_FILE" <<EOF
============================================================
NORDIC MANUFACTURING A/S
SIMULATED INCIDENT DATA
============================================================

Incident ID:
$INCIDENT_ID

Source host:
$HOSTNAME_VALUE

Classification:
CONFIDENTIAL

Dataset:
Synthetic CyberLab Training Data

CUSTOMER_ID,NAME,EMAIL,ORDER_VALUE
NM-1001,Anna Jensen,anna.jensen@example.invalid,12450
NM-1002,Lars Hansen,lars.hansen@example.invalid,8995
NM-1003,Mette Nielsen,mette.nielsen@example.invalid,17400
NM-1004,Peter Sørensen,peter.sorensen@example.invalid,6300
NM-1005,Sofie Larsen,sofie.larsen@example.invalid,22150

------------------------------------------------------------
INTERNAL SYSTEM INFORMATION
------------------------------------------------------------

ERP-System: NordicERP
Production-System: NordicMES
Webshop: NordicShop
Environment: CyberLab

------------------------------------------------------------
TRAINING NOTICE
------------------------------------------------------------

This file contains synthetic data generated for the
Nordic Manufacturing H3 cybersecurity training campaign.

No real customer or employee data is contained in this file.
EOF

chmod 600 "$REMOTE_FILE"

SIZE="$(wc -c < "$REMOTE_FILE")"

HASH=""

if command -v sha256sum >/dev/null 2>&1; then
    HASH="$(sha256sum "$REMOTE_FILE" | awk "{print \$1}")"
fi

printf "NORDIC_STAGING_OK|%s|%s|%s\n" \
    "$REMOTE_FILE" \
    "$SIZE" \
    "$HASH"
'


    RESULT="$(
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
            bash -s -- \
                "$INCIDENT_ID" \
                "$REMOTE_DIR" \
                "$REMOTE_FILE" \
            <<< "$REMOTE_SCRIPT" \
            2>/dev/null
    )"

    SSH_RESULT=$?


    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    if [[ $SSH_RESULT -eq 0 ]] &&
       grep -q '^NORDIC_STAGING_OK|' <<< "$RESULT"; then

        STAGING_RESULT="$(
            printf '%s\n' "$RESULT" |
            grep '^NORDIC_STAGING_OK|' |
            tail -n 1
        )"

        IFS='|' read -r \
            STATUS \
            STAGED_FILE \
            FILE_SIZE \
            FILE_HASH \
            <<< "$STAGING_RESULT"


        STAGED_COUNT=$(( STAGED_COUNT + 1 ))


        log "[+] Data staged successfully on $HOST"
        log "    File: $STAGED_FILE"
        log "    Size: $FILE_SIZE bytes"

        if [[ -n "$FILE_HASH" ]]; then
            log "    SHA256: $FILE_HASH"
        fi


        printf '%s|%s|%s|%s|%s|%s\n' \
            "$HOST" \
            "$SSH_PORT" \
            "$SSH_USER" \
            "$STAGED_FILE" \
            "$FILE_SIZE" \
            "$FILE_HASH" \
            >> "$TMP_RESULTS"


        ground_truth \
            "STAGING_SUCCESS host=$HOST file=$STAGED_FILE size=$FILE_SIZE sha256=$FILE_HASH"

    else

        FAILED_COUNT=$(( FAILED_COUNT + 1 ))

        log "[WARNING] Data staging failed on $HOST"

        ground_truth \
            "STAGING_FAILED host=$HOST"

    fi

done


# ============================================================
# CREATE staged-data.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$STAGING_STATE" \
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

        ip, port, user, path, size, sha256 = line.split("|", 5)

        hosts.append(
            {
                "ip": ip,
                "ssh_port": int(port),
                "ssh_user": user,
                "staged": True,
                "file": path,
                "size": int(size),
                "sha256": sha256,
                "data_type": "synthetic-training-data",
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
echo " PHASE 05 COMPLETED"
echo "============================================================"
echo

echo "Compromised hosts:"
echo "  ${#COMPROMISED[@]}"

echo

echo "Successfully staged:"
echo "  $STAGED_COUNT"

echo

echo "Failed:"
echo "  $FAILED_COUNT"

echo

echo "Staging inventory:"
echo "  $STAGING_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE compromised=${#COMPROMISED[@]} staged=$STAGED_COUNT failed=$FAILED_COUNT"


exit 0