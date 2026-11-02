#!/usr/bin/env bash
# ATTACK_ID="14"
# ATTACK_NAME="Command & Control Simulation"
# ATTACK_ALIAS="c2"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,platform,transport,beacon_interval,beacon_jitter,beacon_count,uri_profile"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Command and Control"
# MITRE_TECHNIQUES="T1071.001"
# MITRE_TECHNIQUE_NAMES="Web Protocols"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 14
