#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 07 - Ransomware / Impact Simulation
#
# SAFE SIMULATION:
# Only operates inside:
#   /opt/nordic-ransomware-lab
#
# No real encryption is performed.
# ============================================================

set -u

LOG_DIR="/opt/nordic-attack/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MANUAL-$TIMESTAMP}"
LOG_FILE="$LOG_DIR/${INCIDENT_ID}-07-ransomware.log"

LAB_DIR="/opt/nordic-ransomware-lab"

echo "======================================================"
echo " Nordic Manufacturing - Phase 07"
echo " Ransomware / Impact Simulation"
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
echo "[*] Lab path    : $LAB_DIR"
echo "[*] Log         : $LOG_FILE"
echo

{
    echo "Incident ID: $INCIDENT_ID"
    echo "Phase: RANSOMWARE / IMPACT"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo "Target: $TARGET"
    echo "Account: $SSH_USER"
    echo "Lab directory: $LAB_DIR"
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
    "$SSH_USER@$TARGET" \
    "true" >/dev/null 2>&1
then
    echo "[ERROR] Unable to access compromised host."
    exit 1
fi

echo "[+] Access confirmed."
echo

# ------------------------------------------------------------
# Prepare safe ransomware lab
# ------------------------------------------------------------

echo "[2/5] Preparing synthetic company files..."

sshpass -p "$SSH_PASSWORD" \
ssh \
-o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null \
"$SSH_USER@$TARGET" \
"sudo bash -s" <<'REMOTE'

LAB="/opt/nordic-ransomware-lab"

# Safety guard
if [[ "$LAB" != "/opt/nordic-ransomware-lab" ]]; then
    echo "SAFETY CHECK FAILED"
    exit 10
fi

rm -rf "$LAB"

mkdir -p "$LAB"/{finance,production,management,shared}

cat > "$LAB/finance/budget-2026.txt" <<'EOF'
Nordic Manufacturing A/S
Synthetic Finance Data

Annual budget: 25,000,000 DKK
Training file only.
EOF

cat > "$LAB/finance/payroll.txt" <<'EOF'
Nordic Manufacturing A/S
Synthetic Payroll Data

This file contains no real employee information.
EOF

cat > "$LAB/production/production-plan.txt" <<'EOF'
Nordic Manufacturing A/S
Synthetic Production Plan

Line A: Normal
Line B: Normal
Line C: Maintenance
EOF

cat > "$LAB/management/strategy.txt" <<'EOF'
Nordic Manufacturing A/S
Synthetic Management Data

Expansion plans
New site
Network modernization
EOF

cat > "$LAB/shared/customers.txt" <<'EOF'
Nordic Manufacturing A/S
Synthetic Customer Data

Example Customer 01
Example Customer 02
Example Customer 03
EOF

chmod -R 777 "$LAB"

echo "Synthetic files created."

REMOTE

echo "[+] Synthetic files prepared."
echo

# ------------------------------------------------------------
# Baseline
# ------------------------------------------------------------

echo "[3/5] Recording file baseline..."

BASELINE=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    "
        echo '=== FILES BEFORE IMPACT ==='

        find '$LAB_DIR' \
            -type f \
            -print \
            -exec sha256sum {} \;

        echo
        echo '=== DIRECTORY ==='

        find '$LAB_DIR' -maxdepth 2 -type f -ls
    " 2>/dev/null)

echo "$BASELINE"

{
    echo "BEFORE IMPACT"
    echo "$BASELINE"
    echo
} >> "$LOG_FILE"

sleep 2

# ------------------------------------------------------------
# Simulate ransomware impact
# ------------------------------------------------------------

echo
echo "[4/5] Simulating ransomware impact..."
echo

IMPACT=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    "LAB='$LAB_DIR' bash -s" <<'REMOTE'

# ------------------------------------------------------------
# HARD SAFETY CHECK
# ------------------------------------------------------------

if [[ "$LAB" != "/opt/nordic-ransomware-lab" ]]; then
    echo "SAFETY CHECK FAILED"
    exit 20
fi

if [[ ! -d "$LAB" ]]; then
    echo "LAB DIRECTORY DOES NOT EXIST"
    exit 21
fi

echo "=== STARTING SAFE IMPACT SIMULATION ==="

find "$LAB" \
    -type f \
    ! -name "*.locked" \
    ! -name "README_RECOVER_FILES.txt" \
    -print0 |
while IFS= read -r -d '' FILE
do

    echo "[SIMULATED-RANSOMWARE-IMPACT]" >> "$FILE"

    mv -- "$FILE" "${FILE}.locked"

    echo "LOCKED: ${FILE}.locked"

done

cat > "$LAB/README_RECOVER_FILES.txt" <<'EOF'
========================================================
          NORDIC MANUFACTURING A/S
          CYBERLAB RANSOMWARE SIMULATION
========================================================

Your files appear to have been locked.

This is a SAFE TRAINING SIMULATION.

No real encryption has been performed.
No payment should be made.
No external attacker is involved.

Incident Response Team should:

1. Identify affected systems
2. Isolate the affected host
3. Investigate initial access
4. Review authentication logs
5. Investigate lateral movement
6. Identify staged/exfiltrated data
7. Restore affected services
8. Document the incident

========================================================
EOF

echo
echo "Ransom note created:"
echo "$LAB/README_RECOVER_FILES.txt"

REMOTE
)

IMPACT_RESULT=$?

echo "$IMPACT"

{
    echo
    echo "IMPACT ACTIVITY"
    echo "$IMPACT"
} >> "$LOG_FILE"

if [[ $IMPACT_RESULT -ne 0 ]]; then
    echo
    echo "[ERROR] Impact simulation failed."
    exit 1
fi

sleep 2

# ------------------------------------------------------------
# Verify impact
# ------------------------------------------------------------

echo
echo "[5/5] Verifying simulated impact..."

AFTER=$(sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$SSH_USER@$TARGET" \
    "
        echo '=== FILES AFTER IMPACT ==='

        find '$LAB_DIR' \
            -type f \
            -print

        echo
        echo '=== LOCKED FILE COUNT ==='

        find '$LAB_DIR' \
            -type f \
            -name '*.locked' |
        wc -l

        echo
        echo '=== RANSOM NOTE ==='

        cat '$LAB_DIR/README_RECOVER_FILES.txt' 2>/dev/null || true

        echo
        echo '=== HASHES AFTER IMPACT ==='

        find '$LAB_DIR' \
            -type f \
            -name '*.locked' \
            -exec sha256sum {} \;
    " 2>/dev/null)

echo "$AFTER"

{
    echo
    echo "AFTER IMPACT"
    echo "$AFTER"
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
    echo "Phase: RANSOMWARE / IMPACT"
    echo "Target: $TARGET"
    echo "Account: $SSH_USER"
    echo
    echo "Affected directory:"
    echo "$LAB_DIR"
    echo
    echo "Activity:"
    echo "- Synthetic company files created"
    echo "- File hashes recorded"
    echo "- File contents modified with simulation marker"
    echo "- Files renamed with .locked extension"
    echo "- Ransom note created"
    echo "- Post-impact file state recorded"
    echo
    echo "SAFETY:"
    echo "No real encryption was performed."
    echo "Only files under:"
    echo "$LAB_DIR"
    echo "were modified."
    echo "=================================================="
} >> "$LOG_FILE"

echo
echo "======================================================"
echo " Phase 07 complete - Impact simulated"
echo "======================================================"
echo
echo "Target       : $TARGET"
echo "Affected     : $LAB_DIR"
echo "Incident ID  : $INCIDENT_ID"
echo "Ground truth : $LOG_FILE"
echo