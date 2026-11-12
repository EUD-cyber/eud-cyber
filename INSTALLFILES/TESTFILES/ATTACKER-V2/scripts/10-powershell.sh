#!/usr/bin/env bash
# ATTACK_ID="10"
# ATTACK_DESCRIPTION="Run optional PowerShell on Windows and Bash on Linux through established remote access."
# ATTACK_TEACHING_PURPOSE="Connect remote command execution to its transport and resulting process activity."
# ATTACK_DETECTION_FOCUS="PowerShell execution|Bash execution|WinRM and SSH sessions"
# ATTACK_PLATFORMS="Windows|Linux"
# ATTACK_PREREQUISITES="Compatible authenticated WinRM or SSH access and execution-time commands. Blank commands are skipped independently for each platform."
# ATTACK_TARGET_TYPE="Authenticated lab hosts"
# ATTACK_CLEANUP="Cleanup depends on the supplied command. No automatic rollback of arbitrary command effects is provided."
# ATTACK_NAME="Custom Remote Command"
# ATTACK_ALIAS="powershell"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout,platform,powershell"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Execution"
# MITRE_TECHNIQUES="T1059.001,T1059.004"
# MITRE_TECHNIQUE_NAMES="PowerShell|Unix Shell"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 10
