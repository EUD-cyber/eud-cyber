#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Full Incident Campaign
#
# Supports:
#
#   MANUAL MODE
#   attackctl -> Full Incident
#
#   AUTO / GUI MODE
#   NORDIC_AUTO=1
#
# Attack chain:
#
#   01 Reconnaissance
#   02 Web Attack
#   03 Initial Access
#   04 Internal Discovery
#   05 Data Staging
#   06 Exfiltration
#   07 Impact / Ransomware Simulation
#
# ============================================================


BASE_DIR="/opt/nordic-attack"
SCRIPT_DIR="$BASE_DIR/scripts"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"


# ============================================================
# MODE
# ============================================================

AUTO_MODE="${NORDIC_AUTO:-0}"


# ============================================================
# FUNCTIONS
# ============================================================

banner() {

    clear 2>/dev/null || true

    echo
    echo "============================================================"
    echo " Nordic Manufacturing A/S"
    echo " H3 FULL INCIDENT CAMPAIGN"
    echo "============================================================"
    echo

}


phase_header() {

    local NUMBER="$1"
    local NAME="$2"

    echo
    echo "============================================================"
    echo " PHASE $NUMBER - $NAME"
    echo "============================================================"
    echo

}


pause_between_phases() {

    # Small variation makes the incident timeline easier
    # for students to investigate afterwards.

    local DELAY=$(( RANDOM % 4 + 2 ))

    echo
    echo "[*] Waiting ${DELAY}s before next phase..."
    echo

    sleep "$DELAY"
}


require_value() {

    local NAME="$1"
    local VALUE="$2"

    if [[ -z "$VALUE" ]]; then

        echo "[ERROR] Missing required value: $NAME"

        exit 1

    fi
}


run_phase() {

    local NUMBER="$1"
    local NAME="$2"
    local SCRIPT="$3"

    phase_header \
        "$NUMBER" \
        "$NAME"

    echo "[*] Starting phase $NUMBER..."
    echo "[*] Script: $SCRIPT"
    echo

    if [[ ! -f "$SCRIPT" ]]; then

        echo "[ERROR] Script not found:"
        echo "$SCRIPT"

        exit 1

    fi

    if [[ ! -x "$SCRIPT" ]]; then

        echo "[ERROR] Script is not executable:"
        echo "$SCRIPT"

        exit 1

    fi


    "$SCRIPT"

    RESULT=$?


    echo

    if [[ $RESULT -ne 0 ]]; then

        echo "============================================================"
        echo " PHASE $NUMBER FAILED"
        echo "============================================================"
        echo
        echo "Phase:"
        echo "$NAME"
        echo
        echo "Exit code:"
        echo "$RESULT"
        echo
        echo "Incident stopped."
        echo

        exit "$RESULT"

    fi


    echo "============================================================"
    echo " PHASE $NUMBER COMPLETED"
    echo "============================================================"
    echo

}


# ============================================================
# BANNER
# ============================================================

banner


# ============================================================
# AUTO / GUI MODE
# ============================================================

if [[ "$AUTO_MODE" == "1" ]]; then

    echo "[MODE] AUTO / WEB GUI"
    echo

    INCIDENT_ID="${NORDIC_INCIDENT_ID:-}"

    COMPROMISED_HOST="${NORDIC_COMPROMISED_HOST:-}"

    WEB_TARGET="${NORDIC_WEB_TARGET:-}"

    WEB_PORT="${NORDIC_WEB_PORT:-80}"

    INTERNAL_TARGET="${NORDIC_INTERNAL_TARGET:-}"

    INCIDENT_IP="${NORDIC_INCIDENT_IP:-}"

    SSH_USER="${NORDIC_SSH_USER:-}"

    SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-}"


# ============================================================
# MANUAL / CLI MODE
# ============================================================

else

    echo "[MODE] MANUAL / CLI"
    echo


    # --------------------------------------------------------
    # Incident ID
    # --------------------------------------------------------

    DEFAULT_INCIDENT_ID=$(
        date +"H3-%Y%m%d-%H%M%S"
    )

    read -r -p \
        "Incident ID [$DEFAULT_INCIDENT_ID]: " \
        INCIDENT_ID

    INCIDENT_ID="${INCIDENT_ID:-$DEFAULT_INCIDENT_ID}"


    echo


    # --------------------------------------------------------
    # Primary compromised host
    # --------------------------------------------------------

    echo "Primary compromised host"
    echo

    read -r -p \
        "Linux target IP: " \
        COMPROMISED_HOST


    echo


    # --------------------------------------------------------
    # Web target
    # --------------------------------------------------------

    echo "Web target"
    echo

    read -r -p \
        "Web target IP [$COMPROMISED_HOST]: " \
        WEB_TARGET

    WEB_TARGET="${WEB_TARGET:-$COMPROMISED_HOST}"


    read -r -p \
        "Web port [80]: " \
        WEB_PORT

    WEB_PORT="${WEB_PORT:-80}"


    echo


    # --------------------------------------------------------
    # Internal target
    # --------------------------------------------------------

    echo "Internal target"
    echo

    read -r -p \
        "Internal target IP: " \
        INTERNAL_TARGET


    echo


    # --------------------------------------------------------
    # IncidentVM
    # --------------------------------------------------------

    echo "IncidentVM / Exfiltration receiver"
    echo

    read -r -p \
        "IncidentVM IP: " \
        INCIDENT_IP


    echo


    # --------------------------------------------------------
    # SSH credentials
    # --------------------------------------------------------

    echo "Compromised host credentials"
    echo

    read -r -p \
        "SSH username [ubuntu]: " \
        SSH_USER

    SSH_USER="${SSH_USER:-ubuntu}"


    read -r -s -p \
        "SSH password: " \
        SSH_PASSWORD

    echo
    echo

fi


# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

require_value \
    "Incident ID" \
    "$INCIDENT_ID"

require_value \
    "Compromised Linux Host" \
    "$COMPROMISED_HOST"

require_value \
    "Web Target" \
    "$WEB_TARGET"

require_value \
    "Web Port" \
    "$WEB_PORT"

require_value \
    "Internal Target" \
    "$INTERNAL_TARGET"

require_value \
    "IncidentVM IP" \
    "$INCIDENT_IP"

require_value \
    "SSH Username" \
    "$SSH_USER"

require_value \
    "SSH Password" \
    "$SSH_PASSWORD"


# ============================================================
# EXPORT CONFIGURATION
#
# Individual phase scripts read these variables.
# ============================================================

export NORDIC_AUTO=1

export NORDIC_INCIDENT_ID="$INCIDENT_ID"

export NORDIC_COMPROMISED_HOST="$COMPROMISED_HOST"

export NORDIC_WEB_TARGET="$WEB_TARGET"

export NORDIC_WEB_PORT="$WEB_PORT"

export NORDIC_INTERNAL_TARGET="$INTERNAL_TARGET"

export NORDIC_INCIDENT_IP="$INCIDENT_IP"

export NORDIC_SSH_USER="$SSH_USER"

export NORDIC_SSH_PASSWORD="$SSH_PASSWORD"


# ============================================================
# MASTER LOG
# ============================================================

MASTER_LOG="$LOG_DIR/${INCIDENT_ID}-FULL-INCIDENT.log"

touch "$MASTER_LOG"

chmod 600 "$MASTER_LOG"


# ============================================================
# CONFIGURATION SUMMARY
# ============================================================

echo
echo "============================================================"
echo " INCIDENT CONFIGURATION"
echo "============================================================"
echo

echo "Incident ID:"
echo "  $INCIDENT_ID"

echo

echo "Compromised Linux Host:"
echo "  $COMPROMISED_HOST"

echo

echo "Web Target:"
echo "  $WEB_TARGET:$WEB_PORT"

echo

echo "Internal Target:"
echo "  $INTERNAL_TARGET"

echo

echo "IncidentVM / Exfiltration Destination:"
echo "  $INCIDENT_IP"

echo

echo "SSH User:"
echo "  $SSH_USER"

echo

echo "Attack chain:"
echo
echo "  01 Reconnaissance"
echo "  02 Web Attack"
echo "  03 Initial Access"
echo "  04 Internal Discovery"
echo "  05 Data Staging"
echo "  06 Exfiltration"
echo "  07 Impact"

echo

echo "Master log:"
echo "  $MASTER_LOG"

echo


# ============================================================
# MANUAL CONFIRMATION
#
# GUI mode must not stop for input.
# ============================================================

if [[ "$AUTO_MODE" != "1" ]]; then

    read -r -p \
        "Start full H3 incident? [y/N]: " \
        CONFIRM

    case "$CONFIRM" in

        y|Y|yes|YES)
            ;;

        *)
            echo
            echo "Incident cancelled."
            exit 0
            ;;

    esac

fi


# ============================================================
# MASTER LOG HEADER
# ============================================================

{

    echo "============================================================"
    echo "NORDIC MANUFACTURING H3 INCIDENT"
    echo "============================================================"

    echo

    echo "Incident ID: $INCIDENT_ID"

    echo "Started:"
    date --iso-8601=seconds

    echo

    echo "Compromised Host: $COMPROMISED_HOST"
    echo "Web Target: $WEB_TARGET:$WEB_PORT"
    echo "Internal Target: $INTERNAL_TARGET"
    echo "IncidentVM: $INCIDENT_IP"
    echo "SSH User: $SSH_USER"

    echo

    echo "Attack chain:"
    echo "01 Reconnaissance"
    echo "02 Web Attack"
    echo "03 Initial Access"
    echo "04 Internal Discovery"
    echo "05 Data Staging"
    echo "06 Exfiltration"
    echo "07 Impact"

    echo

} >> "$MASTER_LOG"


# ============================================================
# START INCIDENT
# ============================================================

echo
echo "============================================================"
echo " FULL INCIDENT STARTED"
echo "============================================================"
echo

echo "Incident ID: $INCIDENT_ID"
echo


# ============================================================
# PHASE 01
# ============================================================

run_phase \
    "01" \
    "RECONNAISSANCE" \
    "$SCRIPT_DIR/01-recon.sh"

echo "$(date --iso-8601=seconds) PHASE01 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 02
# ============================================================

run_phase \
    "02" \
    "WEB ATTACK" \
    "$SCRIPT_DIR/02-web.sh"

echo "$(date --iso-8601=seconds) PHASE02 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 03
# ============================================================

run_phase \
    "03" \
    "INITIAL ACCESS" \
    "$SCRIPT_DIR/03-auth.sh"

echo "$(date --iso-8601=seconds) PHASE03 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 04
# ============================================================

run_phase \
    "04" \
    "INTERNAL DISCOVERY" \
    "$SCRIPT_DIR/04-lateral.sh"

echo "$(date --iso-8601=seconds) PHASE04 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 05
# ============================================================

run_phase \
    "05" \
    "DATA STAGING" \
    "$SCRIPT_DIR/05-staging.sh"

echo "$(date --iso-8601=seconds) PHASE05 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 06
# ============================================================

run_phase \
    "06" \
    "EXFILTRATION" \
    "$SCRIPT_DIR/06-exfil.sh"

echo "$(date --iso-8601=seconds) PHASE06 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 07
# ============================================================

run_phase \
    "07" \
    "IMPACT / RANSOMWARE SIMULATION" \
    "$SCRIPT_DIR/07-ransomware-sim.sh"

echo "$(date --iso-8601=seconds) PHASE07 COMPLETE" \
    >> "$MASTER_LOG"


# ============================================================
# COMPLETION
#
# app.py searches for:
#
# FULL INCIDENT COMPLETED
# ============================================================

{

    echo
    echo "FULL INCIDENT COMPLETED"

    echo "Completed:"
    date --iso-8601=seconds

} >> "$MASTER_LOG"


echo
echo "============================================================"
echo " FULL INCIDENT COMPLETED"
echo "============================================================"
echo

echo "Incident ID:"
echo "  $INCIDENT_ID"

echo

echo "Master log:"
echo "  $MASTER_LOG"

echo

echo "Phase logs:"
echo "  $LOG_DIR"

echo

echo "Exfiltrated files:"
echo "  $BASE_DIR/uploads"

echo

exit 0