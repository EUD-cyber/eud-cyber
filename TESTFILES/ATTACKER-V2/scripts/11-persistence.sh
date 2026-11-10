#!/usr/bin/env bash
# ATTACK_ID="11"
# ATTACK_DESCRIPTION="Create, inspect or clean up Linux user services and bounded visible processes, plus paired persistence with optional lab DNS."
# ATTACK_TEACHING_PURPOSE="Distinguish bounded process execution from persistence; verify target ownership, activity and cleanup."
# ATTACK_DETECTION_FOCUS="Scheduled Task changes|Service creation|Cron or systemd changes|Internal lab DNS queries when enabled"
# ATTACK_PLATFORMS="Windows|Linux"
# ATTACK_PREREQUISITES="Authenticated access with rights for the selected persistence method; auto mode uses P03 access."
# ATTACK_TARGET_TYPE="Authenticated lab hosts"
# ATTACK_CLEANUP="Use Cleanup with the same target, username, method and artifact suffix. Ownership markers limit removal to exercise artifacts. Paired activity stops at its fixed deadline, independent of phase completion; task/cron, service and files require manual Cleanup."
# ATTACK_NAME="Persistence"
# ATTACK_ALIAS="persistence"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout,platform,method,action,artifact,persistence_dns,persistence_domain,persistence_resolver,persistence_interval,persistence_duration,persistence_cpu"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Persistence"
# MITRE_TECHNIQUES="T1053.005,T1543.003,T1053.003,T1543.002,T1059.006"
# MITRE_TECHNIQUE_NAMES="Scheduled Task|Windows Service|Cron|Systemd Service|Python"
set -eu
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/remote_actions.py" 11
