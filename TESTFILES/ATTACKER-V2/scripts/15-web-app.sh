#!/usr/bin/env bash
# ATTACK_ID="15"
# ATTACK_DESCRIPTION="Exercise SQL injection or path traversal against the fingerprinted MrNobody Web Lab."
# ATTACK_TEACHING_PURPOSE="Correlate application requests with a verified synthetic application response."
# ATTACK_DETECTION_FOCUS="Web request patterns|Lab application access logs|Synthetic response markers"
# ATTACK_PLATFORMS="Web"
# ATTACK_PREREQUISITES="Dedicated fingerprinted MrNobody Web Lab endpoint; auto mode consumes P02 web services. General web services are not treated as exploitable."
# ATTACK_TARGET_TYPE="MrNobody Web Lab"
# ATTACK_CLEANUP="Requests use the dedicated synthetic lab endpoint; local response evidence is retained."
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
