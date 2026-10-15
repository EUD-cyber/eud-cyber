#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Full Incident Campaign
#
# Supports multiple compromised Linux hosts:
#
#   192.168.1.20
#   192.168.1.20,192.168.1.21
#
# Attack chain:
#
#   01 Reconnaissance       -> each compromised host
#   02 Web Attack           -> web target once
#   03 Initial Access       -> each compromised host
#   04 Internal Discovery   -> each compromised host
#   05 Data Staging         -> each compromised host
#   06 Exfiltration         -> each compromised host
#   07 Impact               -> each compromised host
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

    if [[ -n "${NORDIC_COMPROMISED_HOST:-}" ]]; then
        echo "[*] Compromised host: $NORDIC_COMPROMISED_HOST"
    fi

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
        echo "Host:"
        echo "${NORDIC_COMPROMISED_HOST:-N/A}"
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


run_phase_for_hosts() {

    local NUMBER="$1"
    local NAME="$2"
    local SCRIPT="$3"

    local HOST

    for HOST in "${COMPROMISED_HOSTS[@]}"; do

        export NORDIC_COMPROMISED_HOST="$HOST"

        echo
        echo "############################################################"
        echo " TARGET HOST: $HOST"
        echo "############################################################"
        echo

        run_phase \
            "$NUMBER" \
            "$NAME - $HOST" \
            "$SCRIPT"

        echo "$(date --iso-8601=seconds) PHASE${NUMBER} HOST=$HOST COMPLETE" \
            >> "$MASTER_LOG"

        pause_between_phases

    done
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

    DEFAULT_INCIDENT_ID=$(
        date +"H3-%Y%m%d-%H%M%S"
    )

    read -r -p \
        "Incident ID [$DEFAULT_INCIDENT_ID]: " \
        INCIDENT_ID

    INCIDENT_ID="${INCIDENT_ID:-$DEFAULT_INCIDENT_ID}"

    echo

    echo "Compromised Linux hosts"
    echo
    echo "Enter one or more IP addresses separated by commas."
    echo "Example:"
    echo "192.168.1.20,192.168.1.21"
    echo

    read -r -p \
        "Linux target IP(s): " \
        COMPROMISED_HOST

    echo

    FIRST_HOST="${COMPROMISED_HOST%%,*}"

    echo "Web target"
    echo

    read -r -p \
        "Web target IP [$FIRST_HOST]: " \
        WEB_TARGET

    WEB_TARGET="${WEB_TARGET:-$FIRST_HOST}"

    read -r -p \
        "Web port [80]: " \
        WEB_PORT

    WEB_PORT="${WEB_PORT:-80}"

    echo

    echo "Internal target"
    echo

    read -r -p \
        "Internal target IP: " \
        INTERNAL_TARGET

    echo

    echo "IncidentVM / Exfiltration receiver"
    echo

    read -r -p \
        "IncidentVM IP: " \
        INCIDENT_IP

    echo

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
    "Compromised Linux Host(s)" \
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
# BUILD HOST ARRAY
# ============================================================

IFS=',' read -r -a RAW_HOSTS <<< "$COMPROMISED_HOST"

COMPROMISED_HOSTS=()

for HOST in "${RAW_HOSTS[@]}"; do

    HOST="${HOST//[[:space:]]/}"

    if [[ -n "$HOST" ]]; then
        COMPROMISED_HOSTS+=("$HOST")
    fi

done


if [[ ${#COMPROMISED_HOSTS[@]} -eq 0 ]]; then

    echo "[ERROR] No compromised hosts configured."
    exit 1

fi


# ============================================================
# EXPORT COMMON CONFIGURATION
# ============================================================

export NORDIC_AUTO=1

export NORDIC_INCIDENT_ID="$INCIDENT_ID"

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

echo "Compromised Linux Hosts:"

for HOST in "${COMPROMISED_HOSTS[@]}"; do
    echo "  $HOST"
done

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
echo "  01 Reconnaissance       - each compromised host"
echo "  02 Web Attack           - web target"
echo "  03 Initial Access       - each compromised host"
echo "  04 Internal Discovery   - each compromised host"
echo "  05 Data Staging         - each compromised host"
echo "  06 Exfiltration         - each compromised host"
echo "  07 Impact               - each compromised host"

echo

echo "Master log:"
echo "  $MASTER_LOG"

echo


# ============================================================
# MANUAL CONFIRMATION
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

    echo "Compromised Hosts:"

    for HOST in "${COMPROMISED_HOSTS[@]}"; do
        echo "  $HOST"
    done

    echo

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

echo "[*] Number of compromised Linux hosts: ${#COMPROMISED_HOSTS[@]}"

for HOST in "${COMPROMISED_HOSTS[@]}"; do
    echo "[*] Host: $HOST"
done

echo


# ============================================================
# PHASE 01 - RECON
# ============================================================

run_phase_for_hosts \
    "01" \
    "RECONNAISSANCE" \
    "$SCRIPT_DIR/01-recon.sh"


# ============================================================
# PHASE 02 - WEB
#
# Run ONCE against configured web target.
# ============================================================

export NORDIC_COMPROMISED_HOST="${COMPROMISED_HOSTS[0]}"

run_phase \
    "02" \
    "WEB ATTACK" \
    "$SCRIPT_DIR/02-web.sh"

echo "$(date --iso-8601=seconds) PHASE02 COMPLETE" \
    >> "$MASTER_LOG"

pause_between_phases


# ============================================================
# PHASE 03 - INITIAL ACCESS
# ============================================================

run_phase_for_hosts \
    "03" \
    "INITIAL ACCESS" \
    "$SCRIPT_DIR/03-auth.sh"


# ============================================================
# PHASE 04 - INTERNAL DISCOVERY
# ============================================================

run_phase_for_hosts \
    "04" \
    "INTERNAL DISCOVERY" \
    "$SCRIPT_DIR/04-lateral.sh"


# ============================================================
# PHASE 05 - DATA STAGING
# ============================================================

run_phase_for_hosts \
    "05" \
    "DATA STAGING" \
    "$SCRIPT_DIR/05-staging.sh"


# ============================================================
# PHASE 06 - EXFILTRATION
# ============================================================

run_phase_for_hosts \
    "06" \
    "EXFILTRATION" \
    "$SCRIPT_DIR/06-exfil.sh"


# ============================================================
# PHASE 07 - IMPACT
# ============================================================

run_phase_for_hosts \
    "07" \
    "IMPACT / RANSOMWARE SIMULATION" \
    "$SCRIPT_DIR/07-ransomware-sim.sh"


# ============================================================
# COMPLETION
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

echo "Compromised hosts:"

for HOST in "${COMPROMISED_HOSTS[@]}"; do
    echo "  $HOST"
done

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
