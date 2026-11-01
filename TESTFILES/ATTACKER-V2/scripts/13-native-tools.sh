#!/usr/bin/env bash
# ATTACK_ID="13"
# ATTACK_NAME="Windows Native Tools / LOLBins Simulation"
# ATTACK_ALIAS="native-tools"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout,behavior"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Execution|Stealth|Persistence"
# MITRE_TECHNIQUES="T1059.001,T1140,T1197"
# MITRE_TECHNIQUE_NAMES="PowerShell|Deobfuscate/Decode Files or Information|BITS Jobs"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 13
