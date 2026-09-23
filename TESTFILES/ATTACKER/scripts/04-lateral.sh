#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 04 - Internal Discovery / Lateral Movement
#
# Purpose:
#   Use an already compromised Linux host to perform internal
#   discovery against another CyberLab system.
#
# Flow:
#
#   IncidentVM
#       |
#       | SSH
#       v
#   Compromised Linux Host
#       |
#       | Internal discovery
#       v
#   Internal Target
#
# Evidence:
#   - SSH session from IncidentVM
#   - Commands executed on compromised host
#   - Network discovery from compromised host
#   - Connections towards another internal system
#
# IMPORTANT:
#   Intended for the Nordic Manufacturing CyberLab only.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/lateral-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | LATERAL | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "   NORDIC MANUFACTURING - INTERNAL DISCOVERY"
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
# Dependencies
# ------------------------------------------------------------

if ! command -v sshpass >/dev/null 2>&1; then
    echo "[ERROR] sshpass is not installed."
    exit 1
fi


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

banner

echo "This phase assumes that a Linux server has already"
echo "been compromised during the previous authentication phase."
echo

echo "The compromised server will perform discovery against"
echo "another internal CyberLab system."
echo


# ------------------------------------------------------------
# Compromised host
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# Internal target
# ------------------------------------------------------------

read -rp "Internal target IP: " INTERNAL_TARGET

if ! validate_ipv4 "$INTERNAL_TARGET"; then
    echo
    echo "[ERROR] Invalid internal target IPv4 address."
    exit 1
fi


echo
echo "Attack path:"
echo
echo "  IncidentVM"
echo "      |"
echo "      | SSH"
echo "      v"
echo "  $COMPROMISED_HOST"
echo "      |"
echo "      | Internal discovery"
echo "      v"
echo "  $INTERNAL_TARGET"
echo


log_event "Lateral movement phase started"
log_event "Compromised host: $COMPROMISED_HOST"
log_event "Internal target: $INTERNAL_TARGET"


{
    echo "============================================================"
    echo "Nordic Manufacturing - Internal Discovery"
    echo "============================================================"
    echo
    echo "Time:             $(date --iso-8601=seconds)"
    echo "AttackVM:         $(hostname)"
    echo "Compromised host: $COMPROMISED_HOST"
    echo "Internal target:  $INTERNAL_TARGET"
    echo
} >> "$LOGFILE"


# ------------------------------------------------------------
# Build remote command
# ------------------------------------------------------------

REMOTE_COMMAND=$(cat <<EOF

echo "===== INTERNAL DISCOVERY ====="
echo

echo "[TIME]"
date --iso-8601=seconds
echo

echo "[CURRENT USER]"
whoami
echo

echo "[HOSTNAME]"
hostname
echo

echo "[IDENTITY]"
id
echo

echo "[NETWORK INTERFACES]"
ip addr
echo

echo "[ROUTING TABLE]"
ip route
echo

echo "[ARP / NEIGHBOURS]"
ip neigh
echo

echo "[DNS CONFIGURATION]"
cat /etc/resolv.conf
echo


echo "===== TARGET DISCOVERY ====="
echo

echo "[PING]"
ping -c 3 -W 1 "$INTERNAL_TARGET" || true
echo


echo "[TCP CONNECTION TESTS]"

for PORT in 22 80 135 139 443 445 3389 8080
do

    echo "Testing $INTERNAL_TARGET:\$PORT"

    timeout 2 bash -c \
        "echo > /dev/tcp/$INTERNAL_TARGET/\$PORT" \
        2>/dev/null \
        && echo "OPEN: $INTERNAL_TARGET:\$PORT" \
        || echo "CLOSED/FILTERED: $INTERNAL_TARGET:\$PORT"

done

echo


echo "[WEB PROBE]"

curl \
    --connect-timeout 3 \
    --max-time 5 \
    -A "Mozilla/5.0" \
    -I \
    "http://$INTERNAL_TARGET/" \
    2>/dev/null || true

echo


echo "===== INTERNAL DISCOVERY COMPLETE ====="

EOF
)


# ------------------------------------------------------------
# Execute from compromised host
# ------------------------------------------------------------

echo
echo "[1/2] Connecting to compromised host..."

log_event "SSH connection from IncidentVM to $COMPROMISED_HOST as $SSH_USER"


sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "$SSH_USER@$COMPROMISED_HOST" \
    "$REMOTE_COMMAND" >> "$LOGFILE" 2>&1

SSH_RESULT=$?


# ------------------------------------------------------------
# Result
# ------------------------------------------------------------

if [[ "$SSH_RESULT" -eq 0 ]]; then

    echo
    echo "[+] Remote execution successful."

    log_event "Internal discovery executed from $COMPROMISED_HOST"
    log_event "$COMPROMISED_HOST probed $INTERNAL_TARGET"

else

    echo
    echo "[ERROR] Could not execute commands on compromised host."

    log_event "Remote discovery FAILED from $COMPROMISED_HOST"

    exit 1

fi


# ------------------------------------------------------------
# Small delay before next incident phase
# ------------------------------------------------------------

echo
echo "[2/2] Internal discovery completed."

sleep 3


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

log_event "Lateral movement phase completed"


echo
echo "============================================================"
echo " Internal discovery completed"
echo "============================================================"
echo
echo "Attack path:"
echo
echo "  IncidentVM"
echo "      |"
echo "      v"
echo "  $COMPROMISED_HOST"
echo "      |"
echo "      v"
echo "  $INTERNAL_TARGET"
echo
echo "Attack log:"
echo "  $LOGFILE"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo