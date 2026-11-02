#!/usr/bin/env bash
# ATTACK_ID="15"
# ATTACK_NAME="Web Exploitation / Application Security Simulation"
# ATTACK_ALIAS="web-app"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,web_profile,web_path"
# ATTACK_CAMPAIGN_STATE="discovered-web-services"
# MITRE_TACTIC="Initial Access,Collection"
# MITRE_TECHNIQUES="T1190,T1005"
# MITRE_TECHNIQUE_NAMES="Exploit Public-Facing Application|Data from Local System"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/web_profiles.py" 15
