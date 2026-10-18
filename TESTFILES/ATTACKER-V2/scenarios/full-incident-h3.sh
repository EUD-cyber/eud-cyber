#!/usr/bin/env bash

set -u


# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Full Dynamic Incident Campaign
#
# Attack chain:
#
#   P1  Dynamic Discovery
#   P2  Web Discovery
#   P3  Initial Access - Linux SSH / Windows RDP
#   P4  Internal Discovery
#   P5  Data Staging
#   P6  Exfiltration
#   P7  Impact
#
# ============================================================


# ============================================================
# PATHS
# ============================================================

BASE_DIR="/opt/nordic-attack"
CONFIG_FILE="$BASE_DIR/config/defaults.conf"
SCRIPT_DIR="$BASE_DIR/scripts"
LOG_DIR="$BASE_DIR/logs"
STATE_DIR="$BASE_DIR/state"
UPLOAD_DIR="$BASE_DIR/uploads"


# ============================================================
# LOAD DEFAULTS
# ============================================================

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found:"
    echo "$CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p \
    "$LOG_DIR" \
    "$STATE_DIR" \
    "$UPLOAD_DIR"


# ============================================================
# INCIDENT ID
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

export NORDIC_INCIDENT_ID="$INCIDENT_ID"


# ============================================================
# GUI / ENVIRONMENT CONFIGURATION
# ============================================================
#
# Values supplied by the Web GUI override defaults.conf.
#
# When the campaign is launched interactively from a terminal,
# missing credentials/settings are requested from the user.
#
# Passwords must NEVER be written to:
#
#   - campaign state
#   - ground truth
#   - campaign log
#
# ============================================================


# ------------------------------------------------------------
# General configuration
# ------------------------------------------------------------

export NORDIC_WEB_PORTS="${NORDIC_WEB_PORTS:-$NORDIC_DEFAULT_WEB_PORTS}"

export NORDIC_EXFIL_PORT="${NORDIC_EXFIL_PORT:-$NORDIC_DEFAULT_EXFIL_PORT}"

export NORDIC_INCIDENT_IP="${NORDIC_INCIDENT_IP:-}"


# ------------------------------------------------------------
# Linux / SSH
#
# Backwards compatibility:
#
# Older V2 components used:
#
#   NORDIC_SSH_USER
#
# New standard:
#
#   NORDIC_SSH_USERNAME
#
# Both are exported for now so existing phase scripts continue
# working while they are migrated.
# ------------------------------------------------------------

if [[ -n "${NORDIC_SSH_USERNAME:-}" ]]; then
    SSH_USERNAME="$NORDIC_SSH_USERNAME"

elif [[ -n "${NORDIC_SSH_USER:-}" ]]; then
    SSH_USERNAME="$NORDIC_SSH_USER"

else
    SSH_USERNAME="$NORDIC_DEFAULT_SSH_USER"
fi

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"

SSH_PORT="${NORDIC_SSH_PORT:-$NORDIC_DEFAULT_SSH_PORT}"


# ------------------------------------------------------------
# Windows / RDP
# ------------------------------------------------------------

RDP_USERNAME="${NORDIC_RDP_USERNAME:-$NORDIC_DEFAULT_RDP_USER}"

RDP_PASSWORD="${NORDIC_RDP_PASSWORD:-$NORDIC_DEFAULT_RDP_PASSWORD}"

RDP_PORT="${NORDIC_RDP_PORT:-$NORDIC_DEFAULT_RDP_PORT}"


# ============================================================
# INTERACTIVE CLI CONFIGURATION
# ============================================================
#
# If stdin is a terminal, the campaign was started manually.
#
# The CLI therefore asks for Linux and Windows credentials.
#
# When Flask/Web GUI launches the script, stdin is not a TTY
# and the values supplied through environment variables are
# used directly.
# ============================================================

if [[ -t 0 ]]; then

    echo
    echo "============================================================"
    echo
    echo "        NORDIC MANUFACTURING A/S"
    echo "        H3 INCIDENT CAMPAIGN V2"
    echo
    echo "        CLI CONFIGURATION"
    echo
    echo "============================================================"
    echo


    # --------------------------------------------------------
    # Linux credentials
    # --------------------------------------------------------

    echo "Linux / SSH"
    echo "-----------"

    read -r -p "Linux username [$SSH_USERNAME]: " INPUT

    if [[ -n "$INPUT" ]]; then
        SSH_USERNAME="$INPUT"
    fi


    read -r -s -p "Linux password: " INPUT_PASSWORD
    echo

    if [[ -n "$INPUT_PASSWORD" ]]; then
        SSH_PASSWORD="$INPUT_PASSWORD"
    fi

    unset INPUT_PASSWORD


    read -r -p "Linux SSH port [$SSH_PORT]: " INPUT

    if [[ -n "$INPUT" ]]; then
        SSH_PORT="$INPUT"
    fi


    echo


    # --------------------------------------------------------
    # Windows credentials
    # --------------------------------------------------------

    echo "Windows / RDP"
    echo "-------------"

    read -r -p "Windows username [$RDP_USERNAME]: " INPUT

    if [[ -n "$INPUT" ]]; then
        RDP_USERNAME="$INPUT"
    fi


    read -r -s -p "Windows password: " INPUT_PASSWORD
    echo

    if [[ -n "$INPUT_PASSWORD" ]]; then
        RDP_PASSWORD="$INPUT_PASSWORD"
    fi

    unset INPUT_PASSWORD


    read -r -p "Windows RDP port [$RDP_PORT]: " INPUT

    if [[ -n "$INPUT" ]]; then
        RDP_PORT="$INPUT"
    fi


    echo


    # --------------------------------------------------------
    # General configuration
    # --------------------------------------------------------

    echo "Campaign configuration"
    echo "----------------------"


    read -r -p "Web ports [$NORDIC_WEB_PORTS]: " INPUT

    if [[ -n "$INPUT" ]]; then
        NORDIC_WEB_PORTS="$INPUT"
    fi


    read -r -p "Exfiltration port [$NORDIC_EXFIL_PORT]: " INPUT

    if [[ -n "$INPUT" ]]; then
        NORDIC_EXFIL_PORT="$INPUT"
    fi


    echo
    echo "Configuration:"
    echo
    echo "  Linux SSH:"
    echo "    Username: $SSH_USERNAME"
    echo "    Port:     $SSH_PORT"
    echo
    echo "  Windows RDP:"
    echo "    Username: $RDP_USERNAME"
    echo "    Port:     $RDP_PORT"
    echo
    echo "  Web ports:"
    echo "    $NORDIC_WEB_PORTS"
    echo
    echo "  Exfiltration port:"
    echo "    $NORDIC_EXFIL_PORT"
    echo

    read -r -p "Start full H3 incident campaign? [y/N]: " CONFIRM

    case "$CONFIRM" in

        y|Y|yes|YES|Yes)
            ;;

        *)
            echo
            echo "Campaign cancelled."
            exit 0
            ;;
    esac

fi


# ============================================================
# EXPORT FINAL CONFIGURATION
# ============================================================
#
# Export both the new variable names and the legacy SSH_USER
# variable until all phase scripts have been migrated.
# ============================================================

export NORDIC_SSH_USERNAME="$SSH_USERNAME"
export NORDIC_SSH_USER="$SSH_USERNAME"
export NORDIC_SSH_PASSWORD="$SSH_PASSWORD"
export NORDIC_SSH_PORT="$SSH_PORT"

export NORDIC_RDP_USERNAME="$RDP_USERNAME"
export NORDIC_RDP_PASSWORD="$RDP_PASSWORD"
export NORDIC_RDP_PORT="$RDP_PORT"

export NORDIC_WEB_PORTS
export NORDIC_EXFIL_PORT


# ============================================================
# VALIDATE PORTS
# ============================================================

validate_port() {

    local PORT="$1"
    local NAME="$2"

    if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
        echo "[ERROR] Invalid $NAME port: $PORT"
        exit 1
    fi

    if (( PORT < 1 || PORT > 65535 )); then
        echo "[ERROR] Invalid $NAME port: $PORT"
        exit 1
    fi
}


validate_port "$NORDIC_SSH_PORT" "SSH"
validate_port "$NORDIC_RDP_PORT" "RDP"
validate_port "$NORDIC_EXFIL_PORT" "exfiltration"


# ============================================================
# MASTER LOG
# ============================================================

MASTER_LOG="$LOG_DIR/${INCIDENT_ID}-campaign.log"

touch "$MASTER_LOG"


log() {

    local MESSAGE="$1"

    echo "$MESSAGE"

    printf '%s %s\n' \
        "$(date --iso-8601=seconds)" \
        "$MESSAGE" \
        >> "$MASTER_LOG"
}


ground_truth() {

    local MESSAGE="$1"

    printf '%s INCIDENT=%s CAMPAIGN %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


# ============================================================
# VALIDATE SCRIPT
# ============================================================

validate_script() {

    local SCRIPT="$1"

    if [[ ! -f "$SCRIPT" ]]; then

        log "[ERROR] Missing phase script:"
        log "        $SCRIPT"

        return 1
    fi


    if [[ ! -x "$SCRIPT" ]]; then

        log "[ERROR] Phase script is not executable:"
        log "        $SCRIPT"

        return 1
    fi


    return 0
}


# ============================================================
# RANDOM DELAY
# ============================================================

phase_delay() {

    local MIN="$NORDIC_PHASE_DELAY_MIN"
    local MAX="$NORDIC_PHASE_DELAY_MAX"

    if (( MAX < MIN )); then
        MAX="$MIN"
    fi

    local DELAY

    DELAY=$(
        python3 - "$MIN" "$MAX" <<'PY'
import random
import sys

minimum = int(sys.argv[1])
maximum = int(sys.argv[2])

print(random.randint(minimum, maximum))
PY
    )

    log "[*] Waiting ${DELAY}s before next phase..."

    sleep "$DELAY"
}


# ============================================================
# RUN PHASE
# ============================================================

run_phase() {

    local NUMBER="$1"
    local NAME="$2"
    local SCRIPT="$3"

    echo
    echo "============================================================"
    echo " PHASE $NUMBER"
    echo " $NAME"
    echo "============================================================"
    echo

    log "[PHASE $NUMBER] START - $NAME"

    ground_truth \
        "PHASE_START phase=$NUMBER name=\"$NAME\""


    "$SCRIPT" 2>&1 | tee -a "$MASTER_LOG"

    # Preserve exit status of phase script rather than tee.

    local RESULT=${PIPESTATUS[0]}


    if [[ $RESULT -ne 0 ]]; then

        echo

        log "[ERROR] Phase $NUMBER failed with exit code $RESULT"

        ground_truth \
            "PHASE_FAILED phase=$NUMBER exit_code=$RESULT"

        return "$RESULT"
    fi


    log "[PHASE $NUMBER] COMPLETE - $NAME"

    ground_truth \
        "PHASE_COMPLETE phase=$NUMBER"

    return 0
}


# ============================================================
# CAMPAIGN BANNER
# ============================================================

clear 2>/dev/null || true

echo
echo "============================================================"
echo
echo "        NORDIC MANUFACTURING A/S"
echo "        H3 INCIDENT CAMPAIGN V2"
echo
echo "============================================================"
echo

echo "Incident ID:"
echo "  $INCIDENT_ID"

echo

echo "Campaign:"
echo "  Dynamic Discovery"

echo

echo "Web / Proxy ports:"
echo "  $NORDIC_WEB_PORTS"

echo

echo "Linux / SSH:"
echo "  User: $NORDIC_SSH_USERNAME"
echo "  Port: $NORDIC_SSH_PORT"

echo

echo "Windows / RDP:"
echo "  User: $NORDIC_RDP_USERNAME"
echo "  Port: $NORDIC_RDP_PORT"

echo

echo "Exfiltration port:"
echo "  $NORDIC_EXFIL_PORT"

echo

echo "Attack chain:"
echo
echo "  P1  Dynamic Discovery"
echo "  P2  Web Discovery"
echo "  P3  Initial Access - Linux SSH / Windows RDP"
echo "  P4  Internal Discovery / Lateral Activity"
echo "  P5  Data Staging"
echo "  P6  Exfiltration"
echo "  P7  Impact"

echo


# ============================================================
# IMPORTANT
#
# Never print Linux or Windows passwords.
# ============================================================

log "[*] Campaign started."
log "[*] Incident ID: $INCIDENT_ID"
log "[*] Web ports: $NORDIC_WEB_PORTS"

log "[*] Linux SSH user: $NORDIC_SSH_USERNAME"
log "[*] Linux SSH port: $NORDIC_SSH_PORT"

log "[*] Windows RDP user: $NORDIC_RDP_USERNAME"
log "[*] Windows RDP port: $NORDIC_RDP_PORT"

log "[*] Exfil port: $NORDIC_EXFIL_PORT"

ground_truth \
    "CAMPAIGN_START version=2.1"


# ============================================================
# VALIDATE ALL PHASE FILES BEFORE STARTING
# ============================================================

PHASE_01="$SCRIPT_DIR/01-discovery.sh"
PHASE_02="$SCRIPT_DIR/02-web.sh"
PHASE_03="$SCRIPT_DIR/03-access.sh"
PHASE_04="$SCRIPT_DIR/04-lateral.sh"
PHASE_05="$SCRIPT_DIR/05-staging.sh"
PHASE_06="$SCRIPT_DIR/06-exfil.sh"
PHASE_07="$SCRIPT_DIR/07-impact.sh"


for SCRIPT in \
    "$PHASE_01" \
    "$PHASE_02" \
    "$PHASE_03" \
    "$PHASE_04" \
    "$PHASE_05" \
    "$PHASE_06" \
    "$PHASE_07"
do

    if ! validate_script "$SCRIPT"; then

        echo
        echo "Campaign aborted."
        echo

        exit 1
    fi

done


# ============================================================
# CLEAN PREVIOUS RUNTIME STATE
#
# Logs are retained.
# Uploads are retained.
#
# Dynamic state from the previous campaign is removed.
# ============================================================

log "[*] Clearing previous campaign state."

rm -f \
    "$NORDIC_NETWORK_STATE" \
    "$NORDIC_DISCOVERED_STATE" \
    "$NORDIC_WEB_STATE" \
    "$NORDIC_COMPROMISED_STATE" \
    "$NORDIC_CAMPAIGN_STATE" \
    "$STATE_DIR/staged-data.json" \
    "$STATE_DIR/exfiltration.json" \
    "$STATE_DIR/impact.json"


# ============================================================
# CREATE INITIAL CAMPAIGN STATE
#
# Credentials/passwords are intentionally NOT stored.
# ============================================================

python3 - \
    "$NORDIC_CAMPAIGN_STATE" \
    "$INCIDENT_ID" \
    "$NORDIC_WEB_PORTS" \
    "$NORDIC_SSH_USERNAME" \
    "$NORDIC_SSH_PORT" \
    "$NORDIC_RDP_USERNAME" \
    "$NORDIC_RDP_PORT" \
    "$NORDIC_EXFIL_PORT" <<'PY'

import json
import sys
from datetime import datetime, timezone

(
    output,
    incident_id,
    web_ports,
    ssh_username,
    ssh_port,
    rdp_username,
    rdp_port,
    exfil_port,
) = sys.argv[1:]

data = {
    "incident_id": incident_id,
    "version": "2.1",
    "campaign": "H3 Incident Campaign V2",
    "mode": "dynamic-discovery",

    "started": datetime.now(
        timezone.utc
    ).isoformat(),

    "status": "running",

    "configuration": {

        "web_ports": [
            int(x.strip())
            for x in web_ports.split(",")
            if x.strip()
        ],

        "linux": {
            "ssh_username": ssh_username,
            "ssh_port": int(ssh_port),
        },

        "windows": {
            "rdp_username": rdp_username,
            "rdp_port": int(rdp_port),
        },

        "exfil_port": int(exfil_port),
    },

    "phases": {
        "01": "pending",
        "02": "pending",
        "03": "pending",
        "04": "pending",
        "05": "pending",
        "06": "pending",
        "07": "pending",
    },
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


# ============================================================
# UPDATE CAMPAIGN STATE
# ============================================================

update_phase_state() {

    local PHASE="$1"
    local STATUS="$2"

    python3 - \
        "$NORDIC_CAMPAIGN_STATE" \
        "$PHASE" \
        "$STATUS" <<'PY'

import json
import sys
from datetime import datetime, timezone

filename = sys.argv[1]
phase = sys.argv[2]
status = sys.argv[3]

with open(filename, encoding="utf-8") as f:
    data = json.load(f)

data.setdefault(
    "phases",
    {}
)[phase] = status

data["updated"] = datetime.now(
    timezone.utc
).isoformat()

with open(filename, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY
}


# ============================================================
# EXECUTE PHASE 01
# ============================================================

update_phase_state "01" "running"

if ! run_phase \
    "01" \
    "Dynamic Network Discovery" \
    "$PHASE_01"
then

    update_phase_state "01" "failed"
    exit 1
fi

update_phase_state "01" "complete"

phase_delay


# ============================================================
# EXECUTE PHASE 02
# ============================================================

update_phase_state "02" "running"

if ! run_phase \
    "02" \
    "Web Discovery" \
    "$PHASE_02"
then

    update_phase_state "02" "failed"
    exit 1
fi

update_phase_state "02" "complete"

phase_delay


# ============================================================
# EXECUTE PHASE 03
# ============================================================

update_phase_state "03" "running"

if ! run_phase \
    "03" \
    "Initial Access - Linux SSH / Windows RDP" \
    "$PHASE_03"
then

    update_phase_state "03" "failed"
    exit 1
fi

update_phase_state "03" "complete"

phase_delay


# ============================================================
# EXECUTE PHASE 04
# ============================================================

update_phase_state "04" "running"

if ! run_phase \
    "04" \
    "Internal Discovery / Lateral Activity" \
    "$PHASE_04"
then

    update_phase_state "04" "failed"
    exit 1
fi

update_phase_state "04" "complete"

phase_delay


# ============================================================
# EXECUTE PHASE 05
# ============================================================

update_phase_state "05" "running"

if ! run_phase \
    "05" \
    "Data Staging" \
    "$PHASE_05"
then

    update_phase_state "05" "failed"
    exit 1
fi

update_phase_state "05" "complete"

phase_delay


# ============================================================
# EXECUTE PHASE 06
# ============================================================

update_phase_state "06" "running"

if ! run_phase \
    "06" \
    "Data Exfiltration" \
    "$PHASE_06"
then

    update_phase_state "06" "failed"
    exit 1
fi

update_phase_state "06" "complete"

phase_delay


# ============================================================
# EXECUTE PHASE 07
# ============================================================

update_phase_state "07" "running"

if ! run_phase \
    "07" \
    "Impact / Ransomware Simulation" \
    "$PHASE_07"
then

    update_phase_state "07" "failed"
    exit 1
fi

update_phase_state "07" "complete"


# ============================================================
# COMPLETE CAMPAIGN
# ============================================================

python3 - \
    "$NORDIC_CAMPAIGN_STATE" <<'PY'

import json
import sys
from datetime import datetime, timezone

filename = sys.argv[1]

with open(filename, encoding="utf-8") as f:
    data = json.load(f)

data["status"] = "complete"

data["completed"] = datetime.now(
    timezone.utc
).isoformat()

with open(filename, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


ground_truth \
    "CAMPAIGN_COMPLETE"


log "[+] Full incident campaign completed."


# ============================================================
# FINAL SUMMARY
# ============================================================

echo
echo "============================================================"
echo
echo "        H3 INCIDENT CAMPAIGN V2 COMPLETE"
echo
echo "============================================================"
echo

echo "Incident:"
echo "  $INCIDENT_ID"

echo

echo "State:"
echo "  $NORDIC_CAMPAIGN_STATE"

echo

echo "Ground truth:"
echo "  $NORDIC_GROUND_TRUTH_LOG"

echo

echo "Master log:"
echo "  $MASTER_LOG"

echo

echo "Dynamic inventories:"
echo

echo "  Networks:"
echo "    $NORDIC_NETWORK_STATE"

echo

echo "  Discovered hosts:"
echo "    $NORDIC_DISCOVERED_STATE"

echo

echo "  Web targets:"
echo "    $NORDIC_WEB_STATE"

echo

echo "  Compromised hosts:"
echo "    $NORDIC_COMPROMISED_STATE"

echo

echo "  Staged data:"
echo "    $STATE_DIR/staged-data.json"

echo

echo "  Exfiltration:"
echo "    $STATE_DIR/exfiltration.json"

echo

echo "  Impact:"
echo "    $STATE_DIR/impact.json"

echo

exit 0