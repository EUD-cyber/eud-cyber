#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 02 - Dynamic Web Discovery / Web Attack
#
# Input:
#
#   state/discovered-hosts.json
#
# Default web/proxy ports:
#
#   80,443,3010,8080,8443
#
# GUI override:
#
#   NORDIC_WEB_PORTS="80,443,3010,8080,8443,9000"
#
# Output:
#
#   state/web-targets.json
#
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
# CAMPAIGN
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-02-web.log"

DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"
WEB_STATE="$NORDIC_WEB_STATE"

WEB_PORTS="${NORDIC_WEB_PORTS:-$NORDIC_DEFAULT_WEB_PORTS}"


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

    printf '%s INCIDENT=%s PHASE=02 %s\n' \
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

for CMD in python3 curl; do

    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[ERROR] Required command not found: $CMD"
        exit 1
    fi

done


# ============================================================
# VALIDATE INPUT
# ============================================================

if [[ ! -f "$DISCOVERED_STATE" ]]; then

    echo "[ERROR] Phase 01 inventory not found:"
    echo "$DISCOVERED_STATE"
    echo
    echo "Run Phase 01 first."

    exit 1
fi


# ============================================================
# PARSE WEB PORTS
# ============================================================

IFS=',' read -r -a RAW_PORTS <<< "$WEB_PORTS"

PORTS=()

for PORT in "${RAW_PORTS[@]}"; do

    PORT="${PORT//[[:space:]]/}"

    [[ -z "$PORT" ]] && continue

    if ! valid_port "$PORT"; then

        echo "[ERROR] Invalid web/proxy port:"
        echo "$PORT"

        exit 1
    fi


    # Avoid duplicates.

    DUPLICATE=0

    for EXISTING in "${PORTS[@]}"; do

        if [[ "$EXISTING" == "$PORT" ]]; then
            DUPLICATE=1
            break
        fi

    done

    if [[ "$DUPLICATE" -eq 0 ]]; then
        PORTS+=("$PORT")
    fi

done


if [[ ${#PORTS[@]} -eq 0 ]]; then

    echo "[ERROR] No web/proxy ports configured."
    exit 1

fi


if (( ${#PORTS[@]} > NORDIC_MAX_WEB_PORTS )); then

    echo "[ERROR] Too many web/proxy ports."
    echo "Maximum: $NORDIC_MAX_WEB_PORTS"

    exit 1
fi


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 02 - WEB DISCOVERY"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Web/proxy ports: ${PORTS[*]}"

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


if [[ ${#HOSTS[@]} -eq 0 ]]; then

    log "[*] No discovered hosts available."

    python3 - "$WEB_STATE" "$INCIDENT_ID" "$WEB_PORTS" <<'PY'
import json
import sys
from datetime import datetime, timezone

output_file = sys.argv[1]
incident_id = sys.argv[2]
ports = sys.argv[3]

data = {
    "incident_id": incident_id,
    "generated": datetime.now(timezone.utc).isoformat(),
    "configured_ports": ports,
    "count": 0,
    "targets": [],
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY

    exit 0
fi


log "[*] Hosts supplied by Phase 01: ${#HOSTS[@]}"

echo


# ============================================================
# TEMPORARY RESULT FILE
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.web-targets.tmp"

: > "$TMP_RESULTS"


# ============================================================
# WEB DISCOVERY
# ============================================================

for HOST in "${HOSTS[@]}"; do

    echo
    echo "------------------------------------------------------------"
    echo " Host: $HOST"
    echo "------------------------------------------------------------"
    echo

    for PORT in "${PORTS[@]}"; do

        # ----------------------------------------------------
        # First determine whether TCP is reachable.
        #
        # Bash /dev/tcp avoids assuming that a configured
        # web port actually contains a web service.
        # ----------------------------------------------------

        if ! timeout "$NORDIC_CONNECT_TIMEOUT" \
            bash -c "echo >/dev/tcp/$HOST/$PORT" \
            >/dev/null 2>&1; then

            continue
        fi


        log "[+] TCP open: $HOST:$PORT"

        ground_truth \
            "WEB_PORT_OPEN ip=$HOST port=$PORT"


        # ----------------------------------------------------
        # Detect HTTP / HTTPS
        #
        # Try HTTPS and HTTP independently.
        #
        # We do not infer protocol purely from the port number.
        # ----------------------------------------------------

        DETECTED_PROTOCOL=""
        HTTP_CODE=""
        SERVER_HEADER=""
        TITLE=""


        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        HTTPS_RESULT="$(
            curl \
                -k \
                -sS \
                --connect-timeout "$NORDIC_HTTP_TIMEOUT" \
                --max-time "$NORDIC_HTTP_TIMEOUT" \
                -o /dev/null \
                -w '%{http_code}' \
                "https://$HOST:$PORT/" \
                2>/dev/null || true
        )"

        if [[ "$HTTPS_RESULT" =~ ^[0-9]{3}$ ]] &&
           [[ "$HTTPS_RESULT" != "000" ]]; then

            DETECTED_PROTOCOL="https"
            HTTP_CODE="$HTTPS_RESULT"

        fi


        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        if [[ -z "$DETECTED_PROTOCOL" ]]; then

            HTTP_RESULT="$(
                curl \
                    -sS \
                    --connect-timeout "$NORDIC_HTTP_TIMEOUT" \
                    --max-time "$NORDIC_HTTP_TIMEOUT" \
                    -o /dev/null \
                    -w '%{http_code}' \
                    "http://$HOST:$PORT/" \
                    2>/dev/null || true
            )"

            if [[ "$HTTP_RESULT" =~ ^[0-9]{3}$ ]] &&
               [[ "$HTTP_RESULT" != "000" ]]; then

                DETECTED_PROTOCOL="http"
                HTTP_CODE="$HTTP_RESULT"

            fi

        fi


        # ----------------------------------------------------
        # Not HTTP/HTTPS
        # ----------------------------------------------------

        if [[ -z "$DETECTED_PROTOCOL" ]]; then

            log "[-] Open port is not HTTP/HTTPS: $HOST:$PORT"

            ground_truth \
                "WEB_SERVICE_REJECTED ip=$HOST port=$PORT reason=not-http"

            continue

        fi


        URL="${DETECTED_PROTOCOL}://${HOST}:${PORT}/"


        # ----------------------------------------------------
        # Obtain response headers
        # ----------------------------------------------------

        HEADERS="$(
            curl \
                -k \
                -sS \
                -I \
                --connect-timeout "$NORDIC_HTTP_TIMEOUT" \
                --max-time "$NORDIC_HTTP_TIMEOUT" \
                "$URL" \
                2>/dev/null || true
        )"

        SERVER_HEADER="$(
            printf '%s\n' "$HEADERS" |
            awk -F': ' '
                BEGIN {IGNORECASE=1}
                /^Server:/ {
                    gsub(/\r/, "", $2)
                    print $2
                    exit
                }
            '
        )"


        # ----------------------------------------------------
        # Obtain page title when possible
        # ----------------------------------------------------

        BODY="$(
            curl \
                -k \
                -sS \
                -L \
                --connect-timeout "$NORDIC_HTTP_TIMEOUT" \
                --max-time "$NORDIC_HTTP_TIMEOUT" \
                --range 0-65535 \
                "$URL" \
                2>/dev/null || true
        )"

        TITLE="$(
            printf '%s' "$BODY" |
            tr '\n' ' ' |
            sed -n \
                's:.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\([^<]*\)</[Tt][Ii][Tt][Ll][Ee]>.*:\1:p' |
            head -n 1
        )"

        TITLE="$(
            printf '%s' "$TITLE" |
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        )"


        # ----------------------------------------------------
        # Store target
        # ----------------------------------------------------

        log "[WEB] $URL HTTP=$HTTP_CODE"

        if [[ -n "$SERVER_HEADER" ]]; then
            log "      Server: $SERVER_HEADER"
        fi

        if [[ -n "$TITLE" ]]; then
            log "      Title: $TITLE"
        fi


        printf '%s|%s|%s|%s|%s|%s\n' \
            "$HOST" \
            "$PORT" \
            "$DETECTED_PROTOCOL" \
            "$HTTP_CODE" \
            "$SERVER_HEADER" \
            "$TITLE" \
            >> "$TMP_RESULTS"


        ground_truth \
            "WEB_TARGET ip=$HOST port=$PORT protocol=$DETECTED_PROTOCOL http_code=$HTTP_CODE"

    done

done


# ============================================================
# CREATE web-targets.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$WEB_STATE" \
    "$INCIDENT_ID" \
    "$WEB_PORTS" <<'PY'

import json
import sys
from datetime import datetime, timezone

source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]
configured_ports = sys.argv[4]

targets = []

with open(source_file, "r", encoding="utf-8") as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue

        parts = line.split("|", 5)

        while len(parts) < 6:
            parts.append("")

        ip, port, protocol, http_code, server, title = parts

        targets.append(
            {
                "ip": ip,
                "port": int(port),
                "protocol": protocol,
                "url": f"{protocol}://{ip}:{port}/",
                "http_code": int(http_code),
                "server": server,
                "title": title,
            }
        )


data = {
    "incident_id": incident_id,
    "generated": datetime.now(timezone.utc).isoformat(),
    "configured_ports": [
        int(p.strip())
        for p in configured_ports.split(",")
        if p.strip()
    ],
    "count": len(targets),
    "targets": targets,
}


with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


rm -f "$TMP_RESULTS"


# ============================================================
# UPDATE discovered-hosts.json
#
# Add detected web services to the central inventory.
# ============================================================

python3 - \
    "$DISCOVERED_STATE" \
    "$WEB_STATE" <<'PY'

import json
import sys

inventory_file = sys.argv[1]
web_file = sys.argv[2]


with open(inventory_file, "r", encoding="utf-8") as f:
    inventory = json.load(f)

with open(web_file, "r", encoding="utf-8") as f:
    web = json.load(f)


targets_by_ip = {}

for target in web.get("targets", []):

    targets_by_ip.setdefault(
        target["ip"],
        []
    ).append(target)


for host in inventory.get("hosts", []):

    ip = host.get("ip")

    targets = targets_by_ip.get(ip, [])

    host["web_candidate"] = bool(targets)

    services = host.setdefault(
        "services",
        {}
    )

    services["web"] = targets


with open(inventory_file, "w", encoding="utf-8") as f:
    json.dump(inventory, f, indent=2)

PY


# ============================================================
# SUMMARY
# ============================================================

WEB_COUNT="$(
    python3 - "$WEB_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

print(data.get("count", 0))
PY
)"


echo
echo "============================================================"
echo " PHASE 02 COMPLETED"
echo "============================================================"
echo

echo "Hosts checked:"
echo "  ${#HOSTS[@]}"

echo

echo "Web/proxy ports:"
echo "  ${PORTS[*]}"

echo

echo "Web services discovered:"
echo "  $WEB_COUNT"

echo

echo "Web inventory:"
echo "  $WEB_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE hosts=${#HOSTS[@]} web_targets=$WEB_COUNT"


exit 0