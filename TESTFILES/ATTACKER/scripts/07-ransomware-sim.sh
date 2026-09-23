#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 07 - Ransomware / Impact Simulation
#
# Purpose:
#   Generate safe ransomware-like forensic evidence on an
#   already compromised Linux CyberLab host.
#
# This script DOES NOT perform real encryption.
#
# It only operates inside:
#
#   /opt/nordic-ransomware-lab/
#
# Evidence:
#   - Rapid file creation/modification
#   - File extensions changed to .locked
#   - Ransom note creation
#   - SHA256 changes
#   - SSH activity
#   - Filesystem activity suitable for FIM
#
# IMPORTANT:
#   Intended for the Nordic Manufacturing CyberLab only.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/ransomware-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"

REMOTE_LAB="/opt/nordic-ransomware-lab"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | IMPACT | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "   NORDIC MANUFACTURING - RANSOMWARE SIMULATION"
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

echo "SAFE ransomware simulation."
echo
echo "No real files will be encrypted."
echo
echo "The simulation only operates inside:"
echo
echo "  $REMOTE_LAB"
echo

read -rp "Compromised host IP: " COMPROMISED_HOST

if ! validate_ipv4 "$COMPROMISED_HOST"; then
    echo
    echo "[ERROR] Invalid IPv4 address."
    exit 1
fi

echo

read -rp "SSH username: " SSH_USER
read -rsp "SSH password: " SSH_PASSWORD

echo
echo

echo "Target:"
echo "  $COMPROMISED_HOST"
echo
echo "Lab directory:"
echo "  $REMOTE_LAB"
echo

log_event "Ransomware simulation started against $COMPROMISED_HOST"


# ------------------------------------------------------------
# Remote simulation
# ------------------------------------------------------------

REMOTE_COMMAND=$(cat <<'EOF'

set -e

LAB="/opt/nordic-ransomware-lab"
DATA="$LAB/company-data"

echo "============================================================"
echo " NORDIC RANSOMWARE IMPACT SIMULATION"
echo "============================================================"
echo

echo "[TIME]"
date --iso-8601=seconds

echo

echo "[USER]"
whoami

echo

echo "[HOST]"
hostname

echo


# ------------------------------------------------------------
# Safety
# ------------------------------------------------------------

if [[ "$LAB" != "/opt/nordic-ransomware-lab" ]]; then
    echo "SAFETY CHECK FAILED"
    exit 1
fi


# ------------------------------------------------------------
# Prepare dedicated lab area
# ------------------------------------------------------------

echo "[+] Preparing isolated ransomware simulation directory"

sudo mkdir -p "$DATA/finance"
sudo mkdir -p "$DATA/hr"
sudo mkdir -p "$DATA/production"
sudo mkdir -p "$DATA/management"

sudo chown -R "$(id -un):$(id -gn)" "$LAB"


# ------------------------------------------------------------
# Create synthetic files
# ------------------------------------------------------------

echo
echo "[+] Creating synthetic company files"


cat > "$DATA/finance/budget-2027.txt" <<'DATAFILE'
NORDIC MANUFACTURING A/S
FINANCE DEPARTMENT

Budget forecast 2027
Production expansion: 4,500,000 DKK
Infrastructure: 1,250,000 DKK
Cybersecurity: 850,000 DKK

CLASSIFICATION: CONFIDENTIAL
DATAFILE


cat > "$DATA/finance/payroll-september.csv" <<'DATAFILE'
employee_id,department,salary
NM001,Finance,48500
NM002,Production,42100
NM003,IT,51750
NM004,Management,68500
DATAFILE


cat > "$DATA/hr/employees.txt" <<'DATAFILE'
Nordic Manufacturing Employee Records

NM001 Anna Jensen - Finance
NM002 Lars Nielsen - Production
NM003 Maria Hansen - IT
NM004 Peter Sorensen - Management

CLASSIFICATION: CONFIDENTIAL
DATAFILE


cat > "$DATA/production/orders.csv" <<'DATAFILE'
order_id,customer,status
PO-1001,Contoso Production,ACTIVE
PO-1002,Fabrikam Logistics,ACTIVE
PO-1003,Northwind Industrial,PENDING
DATAFILE


cat > "$DATA/production/production-plan.txt" <<'DATAFILE'
Nordic Manufacturing Production Plan

Line 1 - Normal operation
Line 2 - Maintenance scheduled
Line 3 - Expansion project

CLASSIFICATION: INTERNAL
DATAFILE


cat > "$DATA/management/strategy.txt" <<'DATAFILE'
NORDIC MANUFACTURING A/S
MANAGEMENT STRATEGY

Confidential strategic planning document.

CLASSIFICATION: CONFIDENTIAL
DATAFILE


# Create additional files to generate FIM activity
for i in $(seq -w 1 20)
do
    echo "Nordic Manufacturing synthetic document $i" \
        > "$DATA/production/document-$i.txt"
done


# ------------------------------------------------------------
# Baseline
# ------------------------------------------------------------

echo
echo "[+] Files before impact"

find "$DATA" -type f -print

echo

echo "[+] Creating baseline hashes"

find "$DATA" \
    -type f \
    -exec sha256sum {} \; \
    > "$LAB/hashes-before.txt"


# ------------------------------------------------------------
# Simulate ransomware impact
# ------------------------------------------------------------

echo
echo "[!] Beginning simulated ransomware impact"

sleep 2


find "$DATA" -type f -print0 |
while IFS= read -r -d '' FILE
do

    ORIGINAL_NAME="$FILE"
    LOCKED_NAME="${FILE}.locked"

    # Modify content so hashes change.
    # This is NOT encryption.
    printf '\n[SIMULATED-RANSOMWARE-IMPACT]\n' >> "$FILE"

    mv "$FILE" "$LOCKED_NAME"

    echo "LOCKED: $ORIGINAL_NAME -> $LOCKED_NAME"

    sleep 0.15

done


# ------------------------------------------------------------
# Ransom note
# ------------------------------------------------------------

cat > "$LAB/README-RECOVER-FILES.txt" <<'NOTE'
============================================================
        NORDIC MANUFACTURING SECURITY INCIDENT
============================================================

Your files are unavailable.

This is a CYBERLAB RANSOMWARE SIMULATION.

No real encryption has been performed.

Incident reference:
INC-H3-RANSOMWARE

Do not use this file as evidence of real ransomware.
============================================================
NOTE


# Copy ransom note into several locations to create evidence

cp "$LAB/README-RECOVER-FILES.txt" \
   "$DATA/README-RECOVER-FILES.txt"

cp "$LAB/README-RECOVER-FILES.txt" \
   "$DATA/finance/README-RECOVER-FILES.txt"

cp "$LAB/README-RECOVER-FILES.txt" \
   "$DATA/production/README-RECOVER-FILES.txt"


# ------------------------------------------------------------
# After-state
# ------------------------------------------------------------

echo
echo "[+] Files after impact"

find "$DATA" -type f -print

echo

echo "[+] Hashing affected files"

find "$DATA" \
    -type f \
    -exec sha256sum {} \; \
    > "$LAB/hashes-after.txt"


# ------------------------------------------------------------
# Incident marker
# ------------------------------------------------------------

cat > "$LAB/INCIDENT.txt" <<MARKER
Incident: INC-H3-RANSOMWARE
Host: $(hostname)
User: $(whoami)
Time: $(date --iso-8601=seconds)
Simulation: Nordic Manufacturing H3
MARKER


echo
echo "============================================================"
echo " SIMULATED IMPACT COMPLETE"
echo "============================================================"

echo
echo "Affected directory:"
echo "$DATA"

echo
echo "Locked files:"
find "$DATA" -type f -name "*.locked" | wc -l

echo

EOF
)


# ------------------------------------------------------------
# Execute simulation
# ------------------------------------------------------------

echo "[1/3] Connecting to compromised host..."

log_event "SSH session opened to $COMPROMISED_HOST for impact phase"


sshpass -p "$SSH_PASSWORD" \
    ssh \
    -tt \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "$SSH_USER@$COMPROMISED_HOST" \
    "$REMOTE_COMMAND" >> "$LOGFILE" 2>&1

SSH_RESULT=$?


if [[ "$SSH_RESULT" -ne 0 ]]; then

    echo
    echo "[ERROR] Ransomware simulation failed."

    log_event "Ransomware simulation FAILED on $COMPROMISED_HOST"

    exit 1

fi


# ------------------------------------------------------------
# Evidence
# ------------------------------------------------------------

echo
echo "[2/3] Impact generated."

log_event "Synthetic files modified and renamed on $COMPROMISED_HOST"

sleep 2


echo
echo "[3/3] Ransom note created."

log_event "Ransom note created on $COMPROMISED_HOST"
log_event "Ransomware simulation completed on $COMPROMISED_HOST"


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

echo
echo "============================================================"
echo " Ransomware simulation completed"
echo "============================================================"
echo
echo "Target:"
echo "  $COMPROMISED_HOST"
echo
echo "Affected directory:"
echo "  $REMOTE_LAB"
echo
echo "Attack log:"
echo "  $LOGFILE"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo