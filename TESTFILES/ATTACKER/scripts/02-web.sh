#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 02 - Web Recon / Suspicious Web Activity
#
# MANUAL:
#   ./02-web.sh
#
# AUTOMATIC:
#   NORDIC_AUTO=1
#   NORDIC_WEB_TARGET=192.168.1.20
#   NORDIC_WEB_PORT=80
#   ./02-web.sh
# ============================================================

set -u

LOG_DIR="/opt/nordic-attack/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MANUAL-$TIMESTAMP}"
LOG_FILE="$LOG_DIR/${INCIDENT_ID}-02-web.log"

echo "======================================================"
echo " Nordic Manufacturing - Phase 02: Web Activity"
echo "======================================================"
echo

# ------------------------------------------------------------
# Input - AUTO or MANUAL
# ------------------------------------------------------------

if [[ "${NORDIC_AUTO:-0}" == "1" ]]; then

    if [[ -z "${NORDIC_WEB_TARGET:-}" ]]; then
        echo "[ERROR] Automatic mode enabled but"
        echo "        NORDIC_WEB_TARGET is not set."
        exit 1
    fi

    TARGET="$NORDIC_WEB_TARGET"
    PORT="${NORDIC_WEB_PORT:-80}"

    echo "[AUTO MODE]"
    echo "Target : $TARGET"
    echo "Port   : $PORT"

else

    echo "[MANUAL MODE]"

    read -rp "Web target IP/hostname: " TARGET
    read -rp "Web port [80]: " PORT

    PORT="${PORT:-80}"

fi

# ------------------------------------------------------------
# Basic validation
# ------------------------------------------------------------

if [[ -z "$TARGET" ]]; then
    echo "[ERROR] No target supplied."
    exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "[ERROR] Invalid TCP port: $PORT"
    exit 1
fi

if [[ "$PORT" == "443" ]]; then
    BASE_URL="https://$TARGET:$PORT"
    CURL_OPTS=(-k -s -o /dev/null)
else
    BASE_URL="http://$TARGET:$PORT"
    CURL_OPTS=(-s -o /dev/null)
fi

echo
echo "[*] Incident ID : $INCIDENT_ID"
echo "[*] Target      : $BASE_URL"
echo "[*] Log         : $LOG_FILE"
echo

{
    echo "Incident ID: $INCIDENT_ID"
    echo "Phase: WEB"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "Target: $TARGET"
    echo "Port: $PORT"
    echo
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Helper function
# ------------------------------------------------------------

send_request() {

    local description="$1"
    local path="$2"

    echo "[>] $description"
    echo "    GET $path"

    STATUS=$(curl "${CURL_OPTS[@]}" \
        -w "%{http_code}" \
        --max-time 5 \
        "$BASE_URL$path" 2>/dev/null || true)

    [[ -z "$STATUS" ]] && STATUS="ERROR"

    echo "    HTTP: $STATUS"
    echo

    {
        echo "[$(date --iso-8601=seconds)]"
        echo "$description"
        echo "GET $path"
        echo "HTTP=$STATUS"
        echo
    } >> "$LOG_FILE"

    sleep 1
}

# ------------------------------------------------------------
# Connectivity check
# ------------------------------------------------------------

echo "[1/5] Checking web service..."

STATUS=$(curl "${CURL_OPTS[@]}" \
    -w "%{http_code}" \
    --max-time 5 \
    "$BASE_URL/" 2>/dev/null || true)

if [[ -z "$STATUS" || "$STATUS" == "000" ]]; then
    echo "[!] Web service did not respond."
    echo "[!] Continuing so the attempt is still documented."
else
    echo "[+] Web service responded with HTTP $STATUS"
fi

echo
sleep 1

# ------------------------------------------------------------
# Normal browsing
# ------------------------------------------------------------

echo "[2/5] Generating normal-looking web traffic..."
echo

send_request \
    "Requesting website root" \
    "/"

send_request \
    "Requesting login page" \
    "/login"

# ------------------------------------------------------------
# Suspicious SQL injection-looking requests
# ------------------------------------------------------------

echo "[3/5] Generating SQL injection indicators..."
echo

send_request \
    "SQL injection-style request" \
    "/login?username=admin%27%20OR%20%271%27=%271&password=test"

send_request \
    "SQL UNION-style request" \
    "/search?q=%27%20UNION%20SELECT%20NULL,NULL--"

# ------------------------------------------------------------
# Suspicious XSS / traversal-looking requests
# ------------------------------------------------------------

echo "[4/5] Generating additional suspicious requests..."
echo

send_request \
    "XSS-style request" \
    "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

send_request \
    "Directory traversal-style request" \
    "/download?file=../../../../etc/passwd"

# ------------------------------------------------------------
# Recon-style requests
# ------------------------------------------------------------

echo "[5/5] Checking common sensitive paths..."
echo

send_request \
    "Requesting admin path" \
    "/admin"

send_request \
    "Requesting configuration-looking file" \
    "/config.php"

send_request \
    "Requesting backup-looking file" \
    "/backup.zip"

# ------------------------------------------------------------
# Ground truth
# ------------------------------------------------------------

{
    echo "=================================================="
    echo "GROUND TRUTH"
    echo "=================================================="
    echo "Incident: $INCIDENT_ID"
    echo "Phase: WEB"
    echo "Source: $(hostname)"
    echo "Target: $TARGET:$PORT"
    echo
    echo "Simulated activity:"
    echo "- Normal web requests"
    echo "- SQL injection indicators"
    echo "- XSS indicator"
    echo "- Directory traversal indicator"
    echo "- Requests for potentially sensitive paths"
    echo
    echo "NOTE:"
    echo "Requests are designed to generate observable"
    echo "security events. This phase does not attempt"
    echo "to modify the target or establish persistence."
    echo "=================================================="
} >> "$LOG_FILE"

echo
echo "======================================================"
echo " Phase 02 complete"
echo "======================================================"
echo
echo "Target       : $TARGET:$PORT"
echo "Incident ID  : $INCIDENT_ID"
echo "Ground truth : $LOG_FILE"
echo