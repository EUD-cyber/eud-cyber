#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 01 - Reconnaissance
#
# Purpose:
#   Simulate attacker reconnaissance against a lab target.
#
# Modes:
#   MANUAL:
#       User enters target IP.
#
#   AUTO:
#       Target is supplied by full-incident-h3.sh through:
#       NORDIC_COMPROMISED_HOST
#
# Evidence:
#   - ICMP traffic
#   - TCP SYN scanning
#   - Service/version detection
#   - Web requests if HTTP/HTTPS is available
#
# IMPORTANT:
#   Intended for the Nordic Manufacturing CyberLab only.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/recon-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | RECON | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "       NORDIC MANUFACTURING - RECONNAISSANCE"
    echo "============================================================"
    echo
}

validate_ipv4() {

    local IP="$1"

    if [[ -z "$IP" ]]; then
        return 1
    fi

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
# Start
# ------------------------------------------------------------

banner

echo "This simulation performs reconnaissance against a lab host."
echo


# ------------------------------------------------------------
# Input
# Manual mode / Full incident automatic mode
# ------------------------------------------------------------

if [[ "${NORDIC_AUTO:-0}" == "1" ]]; then

    # --------------------------------------------------------
    # Automatic mode
    # --------------------------------------------------------

    if [[ -z "${NORDIC_COMPROMISED_HOST:-}" ]]; then

        echo "[ERROR] Automatic mode enabled but"
        echo "        NORDIC_COMPROMISED_HOST is not set."

        exit 1

    fi

    TARGET="$NORDIC_COMPROMISED_HOST"

    echo "[AUTO MODE]"
    echo
    echo "Target supplied by Full H3 Incident:"
    echo
    echo "  $TARGET"
    echo

else

    # --------------------------------------------------------
    # Manual mode
    # --------------------------------------------------------

    echo "[MANUAL MODE]"
    echo

    read -rp "Target IP: " TARGET

fi


# ------------------------------------------------------------
# Validate target
# ------------------------------------------------------------

if ! validate_ipv4 "$TARGET"; then

    echo
    echo "[ERROR] Invalid IPv4 address:"
    echo
    echo "  $TARGET"
    echo

    exit 1

fi


# ------------------------------------------------------------
# Attack information
# ------------------------------------------------------------

echo
echo "Target: $TARGET"
echo "Log:    $LOGFILE"
echo

log_event "Reconnaissance started against $TARGET"

{
    echo "============================================================"
    echo "Nordic Manufacturing - Reconnaissance"
    echo "============================================================"
    echo
    echo "Time:   $(date --iso-8601=seconds)"
    echo "Source: $(hostname)"
    echo "Target: $TARGET"
    echo
} >> "$LOGFILE"


# ------------------------------------------------------------
# Phase 1 - Host discovery
# ------------------------------------------------------------

echo "[1/4] Host discovery..."

log_event "ICMP host discovery against $TARGET"

{
    echo
    echo "===== HOST DISCOVERY ====="

    ping \
        -c 3 \
        -W 1 \
        "$TARGET"

} >> "$LOGFILE" 2>&1

sleep 2


# ------------------------------------------------------------
# Phase 2 - Common TCP ports
# ------------------------------------------------------------

echo "[2/4] Scanning common TCP ports..."

log_event "TCP SYN scan started against $TARGET"

{
    echo
    echo "===== TCP PORT SCAN ====="

    sudo nmap \
        -sS \
        -Pn \
        -T3 \
        --reason \
        -p 21,22,23,25,53,80,110,135,139,143,389,443,445,636,1433,3306,3389,5432,8080,8443 \
        "$TARGET"

} >> "$LOGFILE" 2>&1

sleep 3


# ------------------------------------------------------------
# Phase 3 - Service detection
# ------------------------------------------------------------

echo "[3/4] Detecting exposed services..."

log_event "Service detection started against $TARGET"

{
    echo
    echo "===== SERVICE DETECTION ====="

    sudo nmap \
        -sV \
        -Pn \
        -T3 \
        --version-light \
        -p 22,80,443,445,3389,8080,8443 \
        "$TARGET"

} >> "$LOGFILE" 2>&1

sleep 3


# ------------------------------------------------------------
# Phase 4 - Web reconnaissance
# ------------------------------------------------------------

echo "[4/4] Checking web services..."

log_event "HTTP reconnaissance against $TARGET"

{
    echo
    echo "===== HTTP RECON ====="

    echo
    echo "--- HTTP :80 ---"

    curl \
        --connect-timeout 3 \
        --max-time 5 \
        -A "Mozilla/5.0" \
        -I \
        "http://$TARGET/" 2>&1 || true


    echo
    echo "--- HTTP :8080 ---"

    curl \
        --connect-timeout 3 \
        --max-time 5 \
        -A "Mozilla/5.0" \
        -I \
        "http://$TARGET:8080/" 2>&1 || true


    echo
    echo "--- HTTPS :443 ---"

    curl \
        -k \
        --connect-timeout 3 \
        --max-time 5 \
        -A "Mozilla/5.0" \
        -I \
        "https://$TARGET/" 2>&1 || true

} >> "$LOGFILE" 2>&1


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

log_event "Reconnaissance completed against $TARGET"

echo
echo "============================================================"
echo " Reconnaissance completed"
echo "============================================================"
echo
echo "Target:"
echo "  $TARGET"
echo
echo "Attack log:"
echo "  $LOGFILE"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo