#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 05 - Data Discovery / Staging
# ============================================================

set -u

LOG_DIR="/opt/nordic-attack/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MANUAL-$TIMESTAMP}"
LOG_FILE="$LOG_DIR/${INCIDENT_ID}-05-staging.log"

echo "======================================================"
echo " Nordic Manufacturing - Phase 05"
echo " Data Discovery / Staging"
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
        NORDIC_SSH_USER \
        NORDIC_SSH_PASSWORD
    do
        if [[ -z "${!VAR:-}" ]]; then
            echo "[ERROR] $VAR is not set."
            exit 1
        fi
    done

    TARGET="$NORDIC_COMPROMISED_HOST"
    SSH_USER="$NORDIC_SSH_USER"
    SSH_PASSWORD="$NORDIC_SSH_PASSWORD"

    echo "[AUTO MODE]"
    echo "Target : $TARGET"
    echo "User   : $SSH_USER"

else

    echo "[MANUAL MODE]"

    read -rp "Compromised Linux host: " TARGET
    read -rp "SSH username: " SSH_USER
    read -rsp "SSH password: " SSH_PASSWORD
    echo

fi

if [[ -z "$TARGET" || -z "$SSH_USER" || -z "$SSH_PASSWORD" ]]; then
    echo "[ERROR] Missing required information."
    exit 1
fi

echo
echo "[*] Incident ID : $INCIDENT_ID"
echo "[*] Target      : $TARGET"
echo "[*] Account     : $SSH_USER"
echo "[*] Log         : $LOG_FILE"
echo

{
    echo "Incident ID: $INCIDENT_ID"
    echo "Phase: DATA DISCOVERY / STAGING"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "Target: $TARGET"
    echo "Account: $SSH_USER"
    echo
} >> "$LOG_FILE"

# ------------------------------------------------------------
# Verify access
# ------------------------------------------------------------

echo "[1/5] Verifying access..."

if ! sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    "$SSH_USER@$TARGET" \
    "true" >/dev/null 2>&1
then
    echo "[ERROR] Unable to access $TARGET."
    exit 1
fi

echo "[+] Access confirmed."
echo

# ------------------------------------------------------------
# Create synthetic company data
# ------------------------------------------------------------

echo "[2/5] Preparing synthetic Nordic Manufacturing data..."

sshpass -p "$SSH_PASSWORD" \
ssh \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
"$SSH_USER@$TARGET" \
'bash -s' <<'REMOTE'

DATA_DIR="$HOME/nordic-company-data"

mkdir -p "$DATA_DIR"

cat > "$DATA_DIR/employees.csv" <<'EOF'
employee_id,name,department,email
1001,Anna Jensen,Finance,anna.jensen@nordic.example
1002,Peter Hansen,Production,peter.hansen@nordic.example
1003,Lars Nielsen,IT,lars.nielsen@nordic.example
1004,Sofie Larsen,Management,sofie.larsen@nordic.example
EOF

cat > "$DATA_DIR/customers.csv" <<'EOF'
customer_id,company,contact
C1001,Example Industries A/S,procurement@example.invalid
C1002,Demo Logistics A/S,office@demo.invalid
C1003,Training Manufacturing A/S,sales@training.invalid
EOF

cat > "$DATA_DIR/network-notes.txt" <<'EOF'
Nordic Manufacturing A/S
INTERNAL TRAINING DATA

Head Office:
LAN1: 192.168.1.0/24
LAN2: 192.168.2.0/24

Security:
Firewall protects network boundaries.
VPN is used for approved remote connectivity.

NOTE:
This file contains synthetic CyberLab information only.
EOF

cat > "$DATA_DIR/management-notes.txt" <<'EOF'
CONFIDENTIAL - TRAINING DATA

Nordic Manufacturing A/S

Planned projects:
- New production site
- Network segmentation improvements
- VPN deployment
- SIEM expansion
- Improved backup procedures

This is synthetic data created for the H3 incident exercise.
EOF

echo "[REMOTE] Synthetic company data prepared."

REMOTE

echo "[+] Synthetic data available."
echo

sleep 2

# ------------------------------------------------------------
# Simulated discovery
# ------------------------------------------------------------

echo "[3/5] Simulating data discovery..."

DISCOVERY=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    '
        echo "=== SEARCHING USER FILES ==="

        find "$HOME/nordic-company-data" \
            -maxdepth 2 \
            -type f \
            2>/dev/null

        echo
        echo "=== FILE DETAILS ==="

        ls -lah "$HOME/nordic-company-data" 2>/dev/null
    ' 2>/dev/null)

echo "$DISCOVERY"

{
    echo "DATA DISCOVERY"
    echo "$DISCOVERY"
    echo
} >> "$LOG_FILE"

sleep 2

# ------------------------------------------------------------
# Stage data
# ------------------------------------------------------------

echo
echo "[4/5] Staging discovered data..."

STAGING_RESULT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    '
        SOURCE="$HOME/nordic-company-data"
        STAGE="/tmp/.cache-update"

        rm -rf "$STAGE"
        mkdir -p "$STAGE/files"

        cp -a "$SOURCE"/. "$STAGE/files/"

        echo "=== STAGED FILES ==="
        find "$STAGE/files" -type f -print

        echo
        echo "=== HASH MANIFEST ==="

        find "$STAGE/files" -type f -print0 \
            | sort -z \
            | xargs -0 sha256sum \
            | tee "$STAGE/manifest.sha256"
    ' 2>/dev/null)

echo "$STAGING_RESULT"

{
    echo
    echo "DATA STAGING"
    echo "$STAGING_RESULT"
} >> "$LOG_FILE"

sleep 2

# ------------------------------------------------------------
# Archive data
# ------------------------------------------------------------

echo
echo "[5/5] Creating staged archive..."

ARCHIVE_RESULT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    '
        STAGE="/tmp/.cache-update"
        ARCHIVE="$STAGE/nordic-data.tar.gz"

        rm -f "$ARCHIVE"

        tar \
            --exclude="nordic-data.tar.gz" \
            -czf "$ARCHIVE" \
            -C "$STAGE" \
            files manifest.sha256

        echo "=== ARCHIVE ==="
        ls -lh "$ARCHIVE"

        echo
        echo "=== SHA256 ==="
        sha256sum "$ARCHIVE"
    ' 2>/dev/null)

echo "$ARCHIVE_RESULT"

{
    echo
    echo "ARCHIVE CREATED"
    echo "$ARCHIVE_RESULT"
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
    echo "Phase: DATA DISCOVERY / STAGING"
    echo "Target: $TARGET"
    echo "Account: $SSH_USER"
    echo
    echo "Synthetic source data:"
    echo "\$HOME/nordic-company-data"
    echo
    echo "Staging directory:"
    echo "/tmp/.cache-update"
    echo
    echo "Archive:"
    echo "/tmp/.cache-update/nordic-data.tar.gz"
    echo
    echo "Activity:"
    echo "- Synthetic company data discovered"
    echo "- Files enumerated"
    echo "- Files copied into staging directory"
    echo "- SHA256 manifest generated"
    echo "- Data compressed into tar.gz archive"
    echo
    echo "IMPORTANT:"
    echo "All company information created by this script"
    echo "is synthetic CyberLab training data."
    echo "=================================================="
} >> "$LOG_FILE"

echo
echo "======================================================"
echo " Phase 05 complete - Data staged"
echo "======================================================"
echo
echo "Target       : $TARGET"
echo "Staging      : /tmp/.cache-update"
echo "Archive      : /tmp/.cache-update/nordic-data.tar.gz"
echo "Incident ID  : $INCIDENT_ID"
echo "Ground truth : $LOG_FILE"
echo