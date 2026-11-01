#!/usr/bin/env bash
# ATTACK_ID="09"
# ATTACK_NAME="Active Directory Privilege Escalation"
# ATTACK_ALIAS="ad-privilege"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Persistence,Privilege Escalation"
# MITRE_TECHNIQUES="T1136.002,T1098.007,T1078.002"
# MITRE_TECHNIQUE_NAMES="Domain Account|Additional Local or Domain Groups|Domain Accounts"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/windows_actions.py" 09
