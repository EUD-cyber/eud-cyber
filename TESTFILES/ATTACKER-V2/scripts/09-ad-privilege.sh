#!/usr/bin/env bash
# ATTACK_ID="09"
# ATTACK_DESCRIPTION="Create or enable the lab mrnobody domain account and verify Domain Admins membership."
# ATTACK_TEACHING_PURPOSE="Correlate domain account changes with privilege and group membership events."
# ATTACK_DETECTION_FOCUS="Domain account creation or enablement|Domain group membership changes|AD management sessions"
# ATTACK_PLATFORMS="Windows"
# ATTACK_PREREQUISITES="A lab domain controller with AD management tools and credentials with account and group management rights. P03 authentication alone does not grant those rights."
# ATTACK_TARGET_TYPE="Lab domain controller"
# ATTACK_CLEANUP="Account and group changes persist. No automated AD rollback is provided; restore the lab account and group state separately."
# ATTACK_NAME="Active Directory Privilege Escalation"
# ATTACK_ALIAS="ad-privilege"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password,timeout"
# ATTACK_CAMPAIGN_STATE="compromised-hosts"
# MITRE_TACTIC="Persistence,Privilege Escalation"
# MITRE_TECHNIQUES="T1136.002,T1098.007,T1078.002"
# MITRE_TECHNIQUE_NAMES="Domain Account|Additional Local or Domain Groups|Domain Accounts"
set -eu
printf '%s\n' 'P09 dispatch started: preparing WinRM worker (credentials omitted).'
trap 'rc=$?; if [ "$rc" -ne 0 ]; then printf "%s\\n" "P09 dispatch failed (exit $rc). Check config/defaults.conf and venv/bin/python with pywinrm/NTLM dependencies." >&2; fi' EXIT
INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"
export NORDIC_INCIDENT_ID="$INCIDENT_ID"
BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"
set -a
source "$BASE_DIR/config/defaults.conf"
set +a
if [[ "${MRNOBODY_RUN_MODE:-}" == "standalone" ]]; then
    export MRNOBODY_PROTOCOL=winrm-http MRNOBODY_PORT=5985
fi
if [[ ! -x "$BASE_DIR/venv/bin/python" ]]; then
    printf '%s\n' 'P09 failed: WinRM Python runtime missing; repair the installation.' >&2
    exit 1
fi
exec "$BASE_DIR/venv/bin/python" "$BASE_DIR/web/windows_actions.py" 09
