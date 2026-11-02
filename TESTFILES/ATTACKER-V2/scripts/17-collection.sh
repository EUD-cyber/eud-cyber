#!/usr/bin/env bash
# ATTACK_ID="17"
# ATTACK_NAME="Collection / Archive"
# ATTACK_ALIAS="collection"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,platform,dataset,archive_name,action"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Collection"
# MITRE_TECHNIQUES="T1005,T1560.002"
# MITRE_TECHNIQUE_NAMES="Data from Local System|Archive via Library"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 17
