#!/usr/bin/env bash
# ATTACK_ID="11"
# ATTACK_NAME="Persistence"
# ATTACK_ALIAS="persistence"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout,platform,method,action,artifact"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Persistence"
# MITRE_TECHNIQUES="T1053.005,T1543.003,T1053.003,T1543.002"
# MITRE_TECHNIQUE_NAMES="Scheduled Task|Windows Service|Cron|Systemd Service"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 11
