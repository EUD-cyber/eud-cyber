#!/usr/bin/env bash
# ATTACK_ID="16"
# ATTACK_NAME="Defense Evasion Simulation"
# ATTACK_ALIAS="defense-evasion"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,platform,behavior,action"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Defense Impairment,Stealth"
# MITRE_TECHNIQUES="T1685,T1070"
# MITRE_TECHNIQUE_NAMES="Disable or Modify Tools|Indicator Removal"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 16
