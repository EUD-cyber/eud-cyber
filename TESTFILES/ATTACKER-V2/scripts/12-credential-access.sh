#!/usr/bin/env bash
# ATTACK_ID="12"
# ATTACK_NAME="Credential Access Simulation"
# ATTACK_ALIAS="credential-access"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout,platform,method"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Credential Access"
# MITRE_TECHNIQUES="T1552.001"
# MITRE_TECHNIQUE_NAMES="Credentials In Files"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 12
