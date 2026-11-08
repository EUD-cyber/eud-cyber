#!/usr/bin/env bash
# ATTACK_ID="03"
# ATTACK_DESCRIPTION="Attempt SSH, RDP or WinRM authentication with supplied lab credentials and record verified access."
# ATTACK_TEACHING_PURPOSE="Separate discovered assets from hosts with successful authenticated access."
# ATTACK_DETECTION_FOCUS="Authentication successes and failures|SSH sessions|RDP logons|WinRM sessions"
# ATTACK_PLATFORMS="Linux|Windows"
# ATTACK_PREREQUISITES="Reachable SSH, RDP or WinRM service and valid lab credentials; auto mode uses P01 discovery."
# ATTACK_TARGET_TYPE="Lab hosts"
# ATTACK_CLEANUP="Authentication evidence is retained. No account rollback action is provided."
# ATTACK_NAME="Initial Access"
# ATTACK_ALIAS="access"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password"
# ATTACK_CAMPAIGN_STATE="discovered-hosts"
# MITRE_TACTIC="Initial Access"
# MITRE_TECHNIQUES="T1078"
# MITRE_TECHNIQUE_NAMES="Valid Accounts"
set -eu
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
export NORDIC_INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/access_pipeline.py" 03
