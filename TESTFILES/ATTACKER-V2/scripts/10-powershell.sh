#!/usr/bin/env bash
# ATTACK_ID="10"
# ATTACK_NAME="Custom Remote Command"
# ATTACK_ALIAS="powershell"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout,platform,powershell"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Execution"
# MITRE_TECHNIQUES="T1059.001,T1059.004"
# MITRE_TECHNIQUE_NAMES="PowerShell|Unix Shell"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 10
