#!/usr/bin/env bash
# ATTACK_ID="12"
# ATTACK_DESCRIPTION="Inspect metadata or read a fixed-marker synthetic credential test file, then remove the temporary file."
# ATTACK_TEACHING_PURPOSE="Detect credential-file access without using real credential material."
# ATTACK_DETECTION_FOCUS="Synthetic credential file access|Remote process creation|Temporary file cleanup"
# ATTACK_PLATFORMS="Windows|Linux"
# ATTACK_PREREQUISITES="Authenticated compatible WinRM or SSH access; auto mode uses P03 access."
# ATTACK_TARGET_TYPE="Synthetic credential test file"
# ATTACK_CLEANUP="The temporary synthetic test file is cleaned up; inspect report evidence if cleanup is unverified."
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
