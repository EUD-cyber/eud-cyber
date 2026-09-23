#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S
# H3 - Full Incident Scenario
#
# Runs:
#   01 Recon
#   02 Web Activity
#   03 Authentication / Initial Access
#   04 Internal Discovery / Lateral Movement
#   05 Data Staging
#   06 Exfiltration
#   07 Ransomware / Impact
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
SCRIPT_DIR="$BASE_DIR/scripts"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

clear

echo "======================================================"
echo "       NORDIC MANUFACTURING A/S"
echo "       H3 FULL INCIDENT SCENARIO"
echo "======================================================"
echo
echo "This scenario will simulate:"
echo
echo "  01  Recon"
echo "  02  Web Activity"
echo "  03  Authentication / Initial Access"
echo "  04  Internal Discovery / Lateral Movement"
echo "  05  Data Discovery / Staging"
echo "  06  Data Exfiltration"
echo "  07  Ransomware / Impact"
echo
echo "All activity must remain inside the CyberLab."
echo

# ------------------------------------------------------------
# Required scripts
# ------------------------------------------------------------

echo "[*] Running pre-flight checks..."

REQUIRED_SCRIPTS=(
    "01-recon.sh"
    "02-web.sh"
    "03-auth.sh"
    "04-lateral.sh"
    "05-staging.sh"
    "06-exfil.sh"
    "07-ransomware-sim.sh"
)

for SCRIPT in "${REQUIRED_SCRIPTS[@]}"; do

    if [[ ! -x "$SCRIPT_DIR/$SCRIPT" ]]; then
        echo
        echo "[ERROR] Missing or non-executable:"
        echo "        $SCRIPT_DIR/$SCRIPT"
        exit 1
    fi

done

for CMD in sshpass curl python3; do

    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo
        echo "[ERROR] Required command missing: $CMD"
        exit 1
    fi

done

echo "[+] Pre-flight checks passed."
echo

# ------------------------------------------------------------
# Incident information
# ------------------------------------------------------------

DEFAULT_INCIDENT_ID="H3-$(date +'%Y%m%d-%H%M%S')"

read -rp "Incident ID [$DEFAULT_INCIDENT_ID]: " INPUT_INCIDENT_ID

NORDIC_INCIDENT_ID="${INPUT_INCIDENT_ID:-$DEFAULT_INCIDENT_ID}"

echo
echo "------------------------------------------------------"
echo " Primary compromised host"
echo "------------------------------------------------------"

read -rp "Linux target IP: " NORDIC_COMPROMISED_HOST

echo
echo "------------------------------------------------------"
echo " Web target"
echo "------------------------------------------------------"

read -rp "Web target IP [$NORDIC_COMPROMISED_HOST]: " NORDIC_WEB_TARGET
NORDIC_WEB_TARGET="${NORDIC_WEB_TARGET:-$NORDIC_COMPROMISED_HOST}"

read -rp "Web port [80]: " NORDIC_WEB_PORT
NORDIC_WEB_PORT="${NORDIC_WEB_PORT:-80}"

echo
echo "------------------------------------------------------"
echo " Internal target"
echo "------------------------------------------------------"

read -rp "Internal target IP: " NORDIC_INTERNAL_TARGET

echo
echo "------------------------------------------------------"
echo " IncidentVM / AttackVM"
echo "------------------------------------------------------"

read -rp "IncidentVM IP for exfiltration: " NORDIC_INCIDENT_IP

echo
echo "------------------------------------------------------"
echo " Compromised account"
echo "------------------------------------------------------"

read -rp "SSH username: " NORDIC_SSH_USER
read -rsp "SSH password: " NORDIC_SSH_PASSWORD
echo

# ------------------------------------------------------------
# Basic validation
# ------------------------------------------------------------

REQUIRED_VALUES=(
    NORDIC_INCIDENT_ID
    NORDIC_COMPROMISED_HOST
    NORDIC_WEB_TARGET
    NORDIC_WEB_PORT
    NORDIC_INTERNAL_TARGET
    NORDIC_INCIDENT_IP
    NORDIC_SSH_USER
    NORDIC_SSH_PASSWORD
)

for VAR in "${REQUIRED_VALUES[@]}"; do

    if [[ -z "${!VAR:-}" ]]; then
        echo
        echo "[ERROR] $VAR cannot be empty."
        exit 1
    fi

done

if ! [[ "$NORDIC_WEB_PORT" =~ ^[0-9]+$ ]] ||
   (( NORDIC_WEB_PORT < 1 || NORDIC_WEB_PORT > 65535 )); then

    echo "[ERROR] Invalid web port."
    exit 1
fi

# ------------------------------------------------------------
# Export automatic-mode variables
# ------------------------------------------------------------

export NORDIC_AUTO=1

export NORDIC_INCIDENT_ID
export NORDIC_COMPROMISED_HOST
export NORDIC_WEB_TARGET
export NORDIC_WEB_PORT
export NORDIC_INTERNAL_TARGET
export NORDIC_INCIDENT_IP
export NORDIC_SSH_USER
export NORDIC_SSH_PASSWORD

MASTER_LOG="$LOG_DIR/${NORDIC_INCIDENT_ID}-FULL-INCIDENT.log"

# ------------------------------------------------------------
# Confirmation
# ------------------------------------------------------------

echo
echo "======================================================"
echo " INCIDENT CONFIGURATION"
echo "======================================================"
echo
echo "Incident ID      : $NORDIC_INCIDENT_ID"
echo "Primary target   : $NORDIC_COMPROMISED_HOST"
echo "Web target       : $NORDIC_WEB_TARGET:$NORDIC_WEB_PORT"
echo "Internal target  : $NORDIC_INTERNAL_TARGET"
echo "IncidentVM       : $NORDIC_INCIDENT_IP"
echo "SSH account      : $NORDIC_SSH_USER"
echo
echo "Password is intentionally not displayed."
echo
echo "======================================================"
echo

read -rp "Start full incident? [y/N]: " CONFIRM

case "$CONFIRM" in
    y|Y|yes|YES)
        ;;
    *)
        echo "Incident cancelled."
        exit 0
        ;;
esac

# ------------------------------------------------------------
# Master log
# ------------------------------------------------------------

{
    echo "=================================================="
    echo "NORDIC MANUFACTURING A/S"
    echo "FULL INCIDENT"
    echo "=================================================="
    echo
    echo "Incident ID: $NORDIC_INCIDENT_ID"
    echo "Started: $(date --iso-8601=seconds)"
    echo
    echo "Primary target: $NORDIC_COMPROMISED_HOST"
    echo "Web target: $NORDIC_WEB_TARGET:$NORDIC_WEB_PORT"
    echo "Internal target: $NORDIC_INTERNAL_TARGET"
    echo "IncidentVM: $NORDIC_INCIDENT_IP"
    echo "SSH user: $NORDIC_SSH_USER"
    echo
} > "$MASTER_LOG"

# ------------------------------------------------------------
# Helper
# ------------------------------------------------------------

run_phase() {

    local NUMBER="$1"
    local NAME="$2"
    local SCRIPT="$3"

    echo
    echo "======================================================"
    echo " PHASE $NUMBER - $NAME"
    echo "======================================================"
    echo

    {
        echo
        echo "PHASE $NUMBER - $NAME"
        echo "Started: $(date --iso-8601=seconds)"
    } >> "$MASTER_LOG"

    "$SCRIPT_DIR/$SCRIPT"

    RESULT=$?

    if [[ $RESULT -ne 0 ]]; then

        echo
        echo "======================================================"
        echo " INCIDENT STOPPED"
        echo "======================================================"
        echo
        echo "Phase $NUMBER failed:"
        echo "$NAME"
        echo

        {
            echo "RESULT: FAILED"
            echo "Exit code: $RESULT"
            echo "Incident stopped: $(date --iso-8601=seconds)"
        } >> "$MASTER_LOG"

        exit "$RESULT"

    fi

    {
        echo "RESULT: SUCCESS"
        echo "Completed: $(date --iso-8601=seconds)"
    } >> "$MASTER_LOG"

    echo
    echo "[+] Phase $NUMBER completed."

}

# ------------------------------------------------------------
# Random pause
# ------------------------------------------------------------

incident_pause() {

    MIN="$1"
    MAX="$2"

    DELAY=$(( RANDOM % (MAX - MIN + 1) + MIN ))

    echo
    echo "[*] Waiting ${DELAY}s before next phase..."
    echo

    sleep "$DELAY"

}

# ------------------------------------------------------------
# Execute attack chain
# ------------------------------------------------------------

run_phase \
    "01" \
    "Reconnaissance" \
    "01-recon.sh"

incident_pause 3 7

run_phase \
    "02" \
    "Web Activity" \
    "02-web.sh"

incident_pause 3 8

run_phase \
    "03" \
    "Authentication / Initial Access" \
    "03-auth.sh"

incident_pause 4 10

run_phase \
    "04" \
    "Internal Discovery / Lateral Movement" \
    "04-lateral.sh"

incident_pause 3 8

run_phase \
    "05" \
    "Data Discovery / Staging" \
    "05-staging.sh"

incident_pause 4 10

run_phase \
    "06" \
    "Data Exfiltration" \
    "06-exfil.sh"

incident_pause 5 12

run_phase \
    "07" \
    "Ransomware / Impact" \
    "07-ransomware-sim.sh"

# ------------------------------------------------------------
# Complete
# ------------------------------------------------------------

{
    echo
    echo "=================================================="
    echo "INCIDENT COMPLETE"
    echo "Completed: $(date --iso-8601=seconds)"
    echo "=================================================="
} >> "$MASTER_LOG"

echo
echo "======================================================"
echo "       FULL INCIDENT COMPLETE"
echo "======================================================"
echo
echo "Incident ID:"
echo "  $NORDIC_INCIDENT_ID"
echo
echo "Master log:"
echo "  $MASTER_LOG"
echo
echo "Phase logs:"
echo "  $LOG_DIR/${NORDIC_INCIDENT_ID}-*.log"
echo
echo "Exfiltrated files:"
echo "  /opt/nordic-attack/uploads/"
echo
echo "The CyberLab is now ready for student investigation."
echo "======================================================"
echo