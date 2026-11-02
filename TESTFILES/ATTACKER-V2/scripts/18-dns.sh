#!/usr/bin/env bash
# ATTACK_ID="18"
# ATTACK_NAME="Advanced C2 / DNS Activity"
# ATTACK_ALIAS="dns"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,platform,dns_behavior,dns_endpoint,dns_domain,dns_pattern,dns_interval,dns_jitter,dns_count,dns_duration"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Command and Control"
# MITRE_TECHNIQUES="T1071.004"
# MITRE_TECHNIQUE_NAMES="DNS"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 18
