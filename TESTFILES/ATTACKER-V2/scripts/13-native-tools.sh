#!/usr/bin/env bash
# ATTACK_ID="13"
# ATTACK_DESCRIPTION="Simulate encoded PowerShell, local certutil decode or an empty BITS job on Windows."
# ATTACK_TEACHING_PURPOSE="Recognize native tool activity and correlate it with bounded lab evidence."
# ATTACK_DETECTION_FOCUS="PowerShell process activity|Certutil decoding|BITS job lifecycle"
# ATTACK_PLATFORMS="Windows"
# ATTACK_PREREQUISITES="Authenticated WinRM access on Windows with the selected native tool available."
# ATTACK_TARGET_TYPE="Windows lab host"
# ATTACK_CLEANUP="Temporary native-tool artifacts are removed and empty BITS jobs are cancelled; inspect cleanup evidence for interrupted runs."
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
