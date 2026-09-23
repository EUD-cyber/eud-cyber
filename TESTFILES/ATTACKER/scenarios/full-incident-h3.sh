#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S
# H3 - Full Integrated Security Incident
#
# Teacher controlled incident orchestration.
#
# Attack chain:
#
#   01 Reconnaissance
#        ↓
#   02 Web Attack
#        ↓
#   03 Authentication / Initial Access
#        ↓
#   04 Internal Discovery / Lateral Activity
#        ↓
#   05 Collection / Staging
#        ↓
#   06 Exfiltration
#        ↓
#   07 Ransomware / Impact
#
# IMPORTANT:
#   Intended for the Nordic Manufacturing CyberLab only.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
SCRIPT_DIR="$BASE_DIR/scripts"
LOG_DIR="$BASE_DIR/logs"
DATA_DIR="$BASE_DIR/data"

mkdir -p "$LOG_DIR" "$DATA_DIR"

GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
SCENARIO_LOG="$LOG_DIR/full-h3-incident-$TIMESTAMP.log"

INCIDENT_ID="INC-H3-$TIMESTAMP"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | SCENARIO | $1" \
        >> "$GROUNDTRUTH"
}

banner() {

    clear

    echo "============================================================"
    echo "       NORDIC MANUFACTURING A/S"
    echo "       H3 INTEGRATED SECURITY INCIDENT"
    echo "============================================================"
    echo
    echo "Incident ID:"
    echo "  $INCIDENT_ID"
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


wait_between_phases() {

    local MIN_SECONDS="$1"
    local MAX_SECONDS="$2"

    local RANGE=$((MAX_SECONDS - MIN_SECONDS + 1))
    local DELAY=$((RANDOM % RANGE + MIN_SECONDS))

    echo
    echo "[*] Waiting before next attack phase..."
    echo

    sleep "$DELAY"
}


run_phase() {

    local NUMBER="$1"
    local NAME="$2"
    local SCRIPT="$3"

    echo
    echo "============================================================"
    echo " PHASE $NUMBER - $NAME"
    echo "============================================================"
    echo

    log_event "Phase $NUMBER started - $NAME"

    if [[ ! -x "$SCRIPT" ]]; then
        chmod +x "$SCRIPT"
    fi

    "$SCRIPT"

    RESULT=$?

    if [[ "$RESULT" -eq 0 ]]; then

        log_event "Phase $NUMBER completed - $NAME"

        echo
        echo "[+] Phase $NUMBER completed."

    else

        log_event "Phase $NUMBER FAILED - $NAME"

        echo
        echo "[ERROR] Phase $NUMBER failed."
        echo

        read -rp "Continue incident anyway? [y/N]: " CONTINUE

        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then

            log_event "Incident stopped by operator"

            exit 1
        fi

    fi
}


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

banner

echo "This scenario will generate a complete security incident"
echo "inside the Nordic Manufacturing CyberLab."
echo
echo "Students should normally NOT see this screen."
echo

echo "The scenario includes:"
echo
echo "  Reconnaissance"
echo "  Web attack"
echo "  Authentication attack"
echo "  Internal discovery"
echo "  Data collection"
echo "  Data exfiltration"
echo "  Ransomware impact"
echo

read -rp "Press ENTER to configure incident..."


# ------------------------------------------------------------
# Compromised Linux host
# ------------------------------------------------------------

echo
echo "------------------------------------------------------------"
echo " PRIMARY COMPROMISED HOST"
echo "------------------------------------------------------------"
echo

read -rp "Primary Linux target IP: " COMPROMISED_HOST

if ! validate_ipv4 "$COMPROMISED_HOST"; then
    echo "[ERROR] Invalid IPv4 address."
    exit 1
fi

echo

read -rp "SSH username: " SSH_USER
read -rsp "SSH password: " SSH_PASSWORD

echo


# ------------------------------------------------------------
# Web target
# ------------------------------------------------------------

echo
echo "------------------------------------------------------------"
echo " WEB TARGET"
echo "------------------------------------------------------------"
echo

read -rp "Web server IP: " WEB_TARGET
read -rp "Web server port [80]: " WEB_PORT

WEB_PORT=${WEB_PORT:-80}

if ! validate_ipv4 "$WEB_TARGET"; then
    echo "[ERROR] Invalid web target."
    exit 1
fi

if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] ||
   (( WEB_PORT < 1 || WEB_PORT > 65535 )); then

    echo "[ERROR] Invalid web port."
    exit 1
fi


# ------------------------------------------------------------
# Internal target
# ------------------------------------------------------------

echo
echo "------------------------------------------------------------"
echo " INTERNAL / LATERAL TARGET"
echo "------------------------------------------------------------"
echo

read -rp "Internal target IP: " INTERNAL_TARGET

if ! validate_ipv4 "$INTERNAL_TARGET"; then
    echo "[ERROR] Invalid internal target."
    exit 1
fi


# ------------------------------------------------------------
# IncidentVM address
# ------------------------------------------------------------

echo
echo "------------------------------------------------------------"
echo " INCIDENTVM"
echo "------------------------------------------------------------"
echo

DEFAULT_INCIDENT_IP=$(hostname -I | awk '{print $1}')

read -rp "IncidentVM IP [$DEFAULT_INCIDENT_IP]: " INCIDENT_IP

INCIDENT_IP=${INCIDENT_IP:-$DEFAULT_INCIDENT_IP}

if ! validate_ipv4 "$INCIDENT_IP"; then
    echo "[ERROR] Invalid IncidentVM IP."
    exit 1
fi


# ------------------------------------------------------------
# Confirmation
# ------------------------------------------------------------

clear

echo "============================================================"
echo " INCIDENT CONFIGURATION"
echo "============================================================"
echo

echo "Incident ID:"
echo "  $INCIDENT_ID"
echo

echo "IncidentVM:"
echo "  $INCIDENT_IP"
echo

echo "Primary compromised host:"
echo "  $COMPROMISED_HOST"
echo

echo "Web target:"
echo "  $WEB_TARGET:$WEB_PORT"
echo

echo "Internal target:"
echo "  $INTERNAL_TARGET"
echo

echo "SSH account:"
echo "  $SSH_USER"
echo

echo "============================================================"
echo

read -rp "Type START to launch incident: " CONFIRM

if [[ "$CONFIRM" != "START" ]]; then
    echo
    echo "Incident cancelled."
    exit 0
fi


# ------------------------------------------------------------
# Save teacher configuration
# ------------------------------------------------------------

cat > "$DATA_DIR/current-incident.conf" <<EOF
INCIDENT_ID=$INCIDENT_ID
INCIDENT_IP=$INCIDENT_IP
COMPROMISED_HOST=$COMPROMISED_HOST
WEB_TARGET=$WEB_TARGET
WEB_PORT=$WEB_PORT
INTERNAL_TARGET=$INTERNAL_TARGET
SSH_USER=$SSH_USER
EOF

chmod 600 "$DATA_DIR/current-incident.conf"


# ------------------------------------------------------------
# Start ground truth
# ------------------------------------------------------------

{
    echo
    echo "============================================================"
    echo "INCIDENT START"
    echo "============================================================"
    echo "$(date --iso-8601=seconds) | INCIDENT | $INCIDENT_ID"
    echo "$(date --iso-8601=seconds) | INCIDENT | AttackVM=$INCIDENT_IP"
    echo "$(date --iso-8601=seconds) | INCIDENT | Primary=$COMPROMISED_HOST"
    echo "$(date --iso-8601=seconds) | INCIDENT | Web=$WEB_TARGET:$WEB_PORT"
    echo "$(date --iso-8601=seconds) | INCIDENT | Internal=$INTERNAL_TARGET"
    echo "============================================================"
} >> "$GROUNDTRUTH"


log_event "Full H3 incident started"


# ------------------------------------------------------------
# Export scenario configuration
#
# Individual scripts will use these variables when running
# as part of the automatic scenario.
# ------------------------------------------------------------

export NORDIC_AUTO=1

export NORDIC_COMPROMISED_HOST="$COMPROMISED_HOST"
export NORDIC_WEB_TARGET="$WEB_TARGET"
export NORDIC_WEB_PORT="$WEB_PORT"

export NORDIC_INTERNAL_TARGET="$INTERNAL_TARGET"

export NORDIC_INCIDENT_IP="$INCIDENT_IP"

export NORDIC_SSH_USER="$SSH_USER"
export NORDIC_SSH_PASSWORD="$SSH_PASSWORD"

export NORDIC_INCIDENT_ID="$INCIDENT_ID"


# ------------------------------------------------------------
# PHASE 01
# Reconnaissance
# ------------------------------------------------------------

run_phase \
    "01" \
    "RECONNAISSANCE" \
    "$SCRIPT_DIR/01-recon.sh"

wait_between_phases 5 12


# ------------------------------------------------------------
# PHASE 02
# Web attack
# ------------------------------------------------------------

run_phase \
    "02" \
    "WEB APPLICATION ATTACK" \
    "$SCRIPT_DIR/02-web.sh"

wait_between_phases 8 15


# ------------------------------------------------------------
# PHASE 03
# Authentication / Initial Access
# ------------------------------------------------------------

run_phase \
    "03" \
    "AUTHENTICATION / INITIAL ACCESS" \
    "$SCRIPT_DIR/03-auth.sh"

wait_between_phases 10 20


# ------------------------------------------------------------
# PHASE 04
# Internal discovery
# ------------------------------------------------------------

run_phase \
    "04" \
    "INTERNAL DISCOVERY / LATERAL ACTIVITY" \
    "$SCRIPT_DIR/04-lateral.sh"

wait_between_phases 8 15


# ------------------------------------------------------------
# PHASE 05
# Collection / staging
# ------------------------------------------------------------

run_phase \
    "05" \
    "DATA COLLECTION / STAGING" \
    "$SCRIPT_DIR/05-staging.sh"

wait_between_phases 10 20


# ------------------------------------------------------------
# PHASE 06
# Exfiltration
# ------------------------------------------------------------

run_phase \
    "06" \
    "DATA EXFILTRATION" \
    "$SCRIPT_DIR/06-exfil.sh"

wait_between_phases 10 20


# ------------------------------------------------------------
# PHASE 07
# Impact
# ------------------------------------------------------------

run_phase \
    "07" \
    "RANSOMWARE / IMPACT" \
    "$SCRIPT_DIR/07-ransomware-sim.sh"


# ------------------------------------------------------------
# Incident complete
# ------------------------------------------------------------

log_event "Full H3 incident completed"


{
    echo "============================================================"
    echo "$(date --iso-8601=seconds) | INCIDENT | INCIDENT COMPLETE"
    echo "============================================================"
} >> "$GROUNDTRUTH"


echo
echo "============================================================"
echo " H3 SECURITY INCIDENT COMPLETE"
echo "============================================================"
echo
echo "Incident ID:"
echo "  $INCIDENT_ID"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo
echo "Scenario log:"
echo "  $SCENARIO_LOG"
echo
echo "The CyberLab is now ready for student investigation."
echo