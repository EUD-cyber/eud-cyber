#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 04 - Internal Discovery / Lateral Movement
# ============================================================

set -u

LOG_DIR="/opt/nordic-attack/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MANUAL-$TIMESTAMP}"
LOG_FILE="$LOG_DIR/${INCIDENT_ID}-04-lateral.log"

echo "======================================================"
echo " Nordic Manufacturing - Phase 04"
echo " Internal Discovery / Lateral Movement"
echo "======================================================"
echo

# ------------------------------------------------------------
# Dependency
# ------------------------------------------------------------

if ! command -v sshpass >/dev/null 2>&1; then
    echo "[ERROR] sshpass is not installed."
    exit 1
fi

# ------------------------------------------------------------
# AUTO / MANUAL
# ------------------------------------------------------------

if [[ "${NORDIC_AUTO:-0}" == "1" ]]; then

    for VAR in \
        NORDIC_COMPROMISED_HOST \
        NORDIC_INTERNAL_TARGET \
        NORDIC_SSH_USER \
        NORDIC_SSH_PASSWORD
    do
        if [[ -z "${!VAR:-}" ]]; then
            echo "[ERROR] $VAR is not set."
            exit 1
        fi
    done

    COMPROMISED_HOST="$NORDIC_COMPROMISED_HOST"
    INTERNAL_TARGET="$NORDIC_INTERNAL_TARGET"
    SSH_USER="$NORDIC_SSH_USER"
    SSH_PASSWORD="$NORDIC_SSH_PASSWORD"

    echo "[AUTO MODE]"
    echo "Compromised host : $COMPROMISED_HOST"
    echo "Internal target  : $INTERNAL_TARGET"
    echo "Account          : $SSH_USER"

else

    echo "[MANUAL MODE]"

    read -rp "Compromised Linux host: " COMPROMISED_HOST
    read -rp "Internal target: " INTERNAL_TARGET
    read -rp "SSH username: " SSH_USER
    read -rsp "SSH password: " SSH_PASSWORD
    echo

fi

if [[ -z "$COMPROMISED_HOST" ||
      -z "$INTERNAL_TARGET" ||
      -z "$SSH_USER" ||
      -z "$SSH_PASSWORD" ]]; then

    echo "[ERROR] Missing required information."
    exit 1
fi

echo
echo "[*] Incident ID     : $INCIDENT_ID"
echo "[*] Pivot host      : $COMPROMISED_HOST"
echo "[*] Internal target : $INTERNAL_TARGET"
echo "[*] Log             : $LOG_FILE"
echo

{
    echo "Incident ID: $INCIDENT_ID"
    echo "Phase: INTERNAL DISCOVERY / LATERAL MOVEMENT"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "Pivot host: $COMPROMISED_HOST"
    echo "Internal target: $INTERNAL_TARGET"
    echo "Account: $SSH_USER"
    echo
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Verify access to compromised host
# ------------------------------------------------------------

echo "[1/5] Verifying access to compromised host..."

if ! sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$SSH_USER@$COMPROMISED_HOST" \
    "true" >/dev/null 2>&1
then
    echo "[ERROR] Unable to access compromised host."
    exit 1
fi

echo "[+] Access confirmed."
echo
sleep 2

# ------------------------------------------------------------
# Host discovery
# ------------------------------------------------------------

echo "[2/5] Running discovery from compromised host..."

DISCOVERY=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$COMPROMISED_HOST" \
    '
        echo "=== HOST ==="
        hostname

        echo
        echo "=== USER ==="
        whoami
        id

        echo
        echo "=== INTERFACES ==="
        ip -brief address 2>/dev/null || true

        echo
        echo "=== ROUTING ==="
        ip route 2>/dev/null || true

        echo
        echo "=== NEIGHBOURS ==="
        ip neigh 2>/dev/null || true

        echo
        echo "=== DNS ==="
        cat /etc/resolv.conf 2>/dev/null || true
    ' 2>/dev/null)

echo "$DISCOVERY"

{
    echo "INTERNAL DISCOVERY"
    echo "$DISCOVERY"
    echo
} >> "$LOG_FILE"

sleep 2

# ------------------------------------------------------------
# Reachability
# ------------------------------------------------------------

echo
echo "[3/5] Testing internal target reachability..."

PING_RESULT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$COMPROMISED_HOST" \
    "ping -c 3 -W 1 '$INTERNAL_TARGET' 2>&1 || true")

echo "$PING_RESULT"

{
    echo "PING TEST"
    echo "$PING_RESULT"
    echo
} >> "$LOG_FILE"

sleep 2

# ------------------------------------------------------------
# Selected service probes
# ------------------------------------------------------------

echo
echo "[4/5] Checking selected services on internal target..."
echo

PORTS=(22 80 443 445 3389)

for PORT in "${PORTS[@]}"; do

    RESULT=$(sshpass -p "$SSH_PASSWORD" \
        ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$SSH_USER@$COMPROMISED_HOST" \
        "timeout 2 bash -c 'echo >/dev/tcp/$INTERNAL_TARGET/$PORT' >/dev/null 2>&1 && echo OPEN || echo CLOSED" \
        2>/dev/null)

    echo "TCP/$PORT : $RESULT"

    echo "[$(date --iso-8601=seconds)] target=$INTERNAL_TARGET port=$PORT result=$RESULT" \
        >> "$LOG_FILE"

    sleep 1

done

# ------------------------------------------------------------
# HTTP probe
# ------------------------------------------------------------

echo
echo "[5/5] Testing HTTP access from compromised host..."

HTTP_RESULT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$COMPROMISED_HOST" \
    "curl -s -I --max-time 4 http://$INTERNAL_TARGET/ 2>/dev/null | head -n 5 || true")

if [[ -n "$HTTP_RESULT" ]]; then
    echo "$HTTP_RESULT"
else
    echo "[*] No HTTP response."
fi

{
    echo
    echo "HTTP PROBE"
    echo "$HTTP_RESULT"
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Ground truth
# ------------------------------------------------------------

{
    echo
    echo "=================================================="
    echo "GROUND TRUTH"
    echo "=================================================="
    echo "Incident: $INCIDENT_ID"
    echo "Phase: INTERNAL DISCOVERY / LATERAL MOVEMENT"
    echo
    echo "AttackVM:"
    echo "$(hostname)"
    echo
    echo "Pivot / compromised host:"
    echo "$COMPROMISED_HOST"
    echo
    echo "Internal target:"
    echo "$INTERNAL_TARGET"
    echo
    echo "Activity:"
    echo "- Logged into previously compromised Linux host"
    echo "- Enumerated interfaces"
    echo "- Enumerated routing table"
    echo "- Enumerated neighbour table"
    echo "- Examined DNS configuration"
    echo "- Tested internal host reachability"
    echo "- Probed TCP/22"
    echo "- Probed TCP/80"
    echo "- Probed TCP/443"
    echo "- Probed TCP/445"
    echo "- Probed TCP/3389"
    echo "- Tested HTTP access"
    echo
    echo "IMPORTANT:"
    echo "This phase simulates internal discovery and"
    echo "preparation for lateral movement."
    echo "It does not exploit the internal target."
    echo "=================================================="
} >> "$LOG_FILE"

echo
echo "======================================================"
echo " Phase 04 complete"
echo "======================================================"
echo
echo "Pivot host    : $COMPROMISED_HOST"
echo "Internal host : $INTERNAL_TARGET"
echo "Incident ID   : $INCIDENT_ID"
echo "Ground truth  : $LOG_FILE"
echo