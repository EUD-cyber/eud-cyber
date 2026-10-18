#!/usr/bin/env bash

set -u


# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 07 - Impact / Ransomware Simulation
#
# Linux:
#   /tmp/nordic-impact-<INCIDENT-ID>/
#
# Windows:
#   C:\NordicIncident\<INCIDENT-ID>\impact\
#
# IMPORTANT:
#
#   Only synthetic files created by this script are affected.
#
#   Existing user/system files are NEVER encrypted,
#   renamed, modified or deleted.
#
#   This is a ransomware INDICATOR simulation.
#   No cryptographic encryption is performed.
# ============================================================


# ============================================================
# PATHS / CONFIG
# ============================================================

BASE_DIR="/opt/nordic-attack"
CONFIG_FILE="$BASE_DIR/config/defaults.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p \
    "$NORDIC_LOG_DIR" \
    "$NORDIC_STATE_DIR"


# ============================================================
# CAMPAIGN CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"

RDP_PASSWORD="${NORDIC_RDP_PASSWORD:-$NORDIC_DEFAULT_RDP_PASSWORD}"

WINRM_HTTP_PORT="${NORDIC_WINRM_HTTP_PORT:-${NORDIC_DEFAULT_WINRM_HTTP_PORT:-5985}}"
WINRM_HTTPS_PORT="${NORDIC_WINRM_HTTPS_PORT:-${NORDIC_DEFAULT_WINRM_HTTPS_PORT:-5986}}"

COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

IMPACT_STATE="$NORDIC_STATE_DIR/impact.json"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-07-impact.log"


# ============================================================
# FUNCTIONS
# ============================================================

log() {

    local MESSAGE="$1"

    echo "$MESSAGE"

    printf '%s %s\n' \
        "$(date --iso-8601=seconds)" \
        "$MESSAGE" \
        >> "$LOG_FILE"
}


ground_truth() {

    local MESSAGE="$1"

    printf '%s INCIDENT=%s PHASE=07 %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


tcp_open() {
    local HOST="$1"
    local PORT="$2"
    local CONNECT_TIMEOUT="${NORDIC_CONNECT_TIMEOUT:-2}"

    timeout "$CONNECT_TIMEOUT" \
        bash -c "echo >/dev/tcp/$HOST/$PORT" \
        >/dev/null 2>&1
}


# ============================================================
# REQUIRED COMMANDS
# ============================================================

for CMD in python3 sshpass ssh timeout; do

    if ! command -v "$CMD" >/dev/null 2>&1; then

        echo "[ERROR] Required command not found: $CMD"
        exit 1

    fi

done


# ============================================================
# WINDOWS SUPPORT
# ============================================================

PYWINRM_AVAILABLE=0

if python3 -c "import winrm" >/dev/null 2>&1; then
    PYWINRM_AVAILABLE=1
fi


# ============================================================
# VALIDATION
# ============================================================

if [[ ! -f "$COMPROMISED_STATE" ]]; then

    echo "[ERROR] Missing compromised host inventory:"
    echo "$COMPROMISED_STATE"
    echo
    echo "Run Phase 03 first."

    exit 1
fi


# ============================================================
# LOAD COMPROMISED HOSTS
#
# Format:
#
# IP|PLATFORM|ACCESS|PORT|USER
#
# Old SSH-only state remains supported.
# ============================================================

mapfile -t COMPROMISED < <(

    python3 - "$COMPROMISED_STATE" <<'PY'
import json
import sys


with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)


for host in data.get("hosts", []):

    if not host.get("compromised"):
        continue

    ip = host.get("ip")

    if not ip:
        continue

    platform = host.get(
        "platform",
        ""
    ).lower()

    access = host.get(
        "access",
        ""
    ).lower()


    # Backwards compatibility
    if not platform:

        if access == "rdp":
            platform = "windows"
        else:
            platform = "linux"


    if platform == "linux":

        port = host.get(
            "ssh_port",
            22
        )

        user = (
            host.get("ssh_username")
            or host.get("ssh_user")
            or "ubuntu"
        )

        print(
            f"{ip}|linux|ssh|{port}|{user}"
        )


    elif platform == "windows":

        port = host.get(
            "rdp_port",
            3389
        )

        user = (
            host.get("rdp_username")
            or host.get("rdp_user")
            or "Administrator"
        )

        print(
            f"{ip}|windows|rdp|{port}|{user}"
        )

PY

)


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 07 - IMPACT / RANSOMWARE SIMULATION"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Compromised hosts: ${#COMPROMISED[@]}"

echo


# ============================================================
# EMPTY CAMPAIGN
# ============================================================

if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."

    python3 - "$IMPACT_STATE" "$INCIDENT_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone


data = {
    "incident_id": sys.argv[2],
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": 0,
    "hosts": [],
}


with open(
    sys.argv[1],
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        data,
        f,
        indent=2
    )

PY

    ground_truth \
        "PHASE_COMPLETE impacted_hosts=0"

    exit 0
fi


# ============================================================
# TEMP RESULT FILE
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.impact.tmp"

: > "$TMP_RESULTS"

SUCCESS_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

LINUX_SUCCESS=0
WINDOWS_SUCCESS=0


# ============================================================
# IMPACT SIMULATION
# ============================================================

for RECORD in "${COMPROMISED[@]}"; do

    IFS='|' read -r \
        HOST \
        PLATFORM \
        ACCESS \
        ACCESS_PORT \
        ACCESS_USER \
        <<< "$RECORD"


    echo
    echo "------------------------------------------------------------"
    echo " Compromised host: $HOST"
    echo " Platform:         $PLATFORM"
    echo "------------------------------------------------------------"
    echo


    log "[*] Starting impact simulation on $HOST ($PLATFORM)"

    ground_truth \
        "IMPACT_START host=$HOST platform=$PLATFORM"


    # ========================================================
    # LINUX
    # ========================================================

    if [[ "$PLATFORM" == "linux" ]]; then


        if [[ -z "$SSH_PASSWORD" ]]; then

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] SSH password unavailable for $HOST"

            ground_truth \
                "IMPACT_FAILED host=$HOST platform=linux reason=missing_credentials"

            continue
        fi


        REMOTE_RESULT="$(
            sshpass -p "$SSH_PASSWORD" \
                ssh \
                    -p "$ACCESS_PORT" \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
                    -o PreferredAuthentications=password \
                    -o PubkeyAuthentication=no \
                    -o NumberOfPasswordPrompts=1 \
                    "$ACCESS_USER@$HOST" \
                    bash -s -- "$INCIDENT_ID" <<'REMOTE'

set -e

INCIDENT_ID="$1"

IMPACT_DIR="/tmp/nordic-impact-${INCIDENT_ID}"

DATA_DIR="$IMPACT_DIR/company-data"


mkdir -p \
    "$DATA_DIR/Finance" \
    "$DATA_DIR/HR" \
    "$DATA_DIR/Production" \
    "$DATA_DIR/Webshop" \
    "$DATA_DIR/Management"


# ============================================================
# SYNTHETIC COMPANY FILES
# ============================================================

cat > "$DATA_DIR/Finance/invoices.csv" <<EOF
Invoice,Customer,Amount
INV-2026-1001,Nordic Customer 01,12500
INV-2026-1002,Nordic Customer 02,8700
INV-2026-1003,Nordic Customer 03,19300
EOF


cat > "$DATA_DIR/HR/employees.csv" <<EOF
EmployeeID,Department,Status
EMP-1001,Production,Active
EMP-1002,IT,Active
EMP-1003,Sales,Active
EOF


cat > "$DATA_DIR/Production/production-plan.txt" <<EOF
Nordic Manufacturing
Production Schedule

Line 1: Running
Line 2: Running
Line 3: Maintenance scheduled
EOF


cat > "$DATA_DIR/Webshop/orders.csv" <<EOF
OrderID,Status
ORD-5001,Processing
ORD-5002,Ready
ORD-5003,Processing
EOF


cat > "$DATA_DIR/Management/business-plan.txt" <<EOF
NORDIC MANUFACTURING A/S

CONFIDENTIAL

Synthetic H3 CyberLab training document.
EOF


for NUMBER in $(seq 1 10); do

    printf \
        "Nordic Manufacturing synthetic training document %s\n" \
        "$NUMBER" \
        > "$DATA_DIR/Management/document-${NUMBER}.txt"

done


# ============================================================
# COUNT BEFORE IMPACT
# ============================================================

BEFORE="$(
    find "$DATA_DIR" \
        -type f \
        | wc -l
)"


# ============================================================
# CONTROLLED IMPACT
#
# ONLY files underneath DATA_DIR are renamed.
# ============================================================

while IFS= read -r -d '' FILE; do

    mv -- \
        "$FILE" \
        "${FILE}.locked"

done < <(
    find "$DATA_DIR" \
        -type f \
        -print0
)


# ============================================================
# RECOVERY NOTE
# ============================================================

cat > "$IMPACT_DIR/README_RECOVER_FILES.txt" <<EOF
============================================================
YOUR FILES ARE UNAVAILABLE
============================================================

Nordic Manufacturing A/S
H3 CyberLab Incident Simulation

Incident:
$INCIDENT_ID

Multiple company files are currently unavailable.

This is a CONTROLLED TRAINING SIMULATION.

No real encryption has been performed.
No real user data has been modified.

Contact the Incident Response Team.

============================================================
EOF


# ============================================================
# RESULT
# ============================================================

LOCKED="$(
    find "$DATA_DIR" \
        -type f \
        -name "*.locked" \
        | wc -l
)"


HOSTNAME_VALUE="$(
    hostname 2>/dev/null ||
    echo unknown
)"


printf \
    "NORDIC_IMPACT_OK|%s|%s|%s|%s\n" \
    "$IMPACT_DIR" \
    "$BEFORE" \
    "$LOCKED" \
    "$HOSTNAME_VALUE"

REMOTE
        )"


        COMMAND_RESULT=$?


        if [[ $COMMAND_RESULT -eq 0 ]] &&
           grep -q '^NORDIC_IMPACT_OK|' <<< "$REMOTE_RESULT"; then


            RESULT_LINE="$(
                printf '%s\n' "$REMOTE_RESULT" |
                grep '^NORDIC_IMPACT_OK|' |
                tail -n 1
            )"


            IFS='|' read -r \
                STATUS \
                IMPACT_DIR \
                ORIGINAL_FILES \
                LOCKED_FILES \
                HOSTNAME_VALUE \
                <<< "$RESULT_LINE"


            SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
            LINUX_SUCCESS=$(( LINUX_SUCCESS + 1 ))


            log "[+] Impact simulation completed on $HOST"
            log "    Platform: Linux"
            log "    Hostname: $HOSTNAME_VALUE"
            log "    Impact directory: $IMPACT_DIR"
            log "    Files affected: $LOCKED_FILES"


            printf '%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "linux" \
                "$HOSTNAME_VALUE" \
                "$IMPACT_DIR" \
                "$ORIGINAL_FILES" \
                "$LOCKED_FILES" \
                >> "$TMP_RESULTS"


            ground_truth \
                "IMPACT_SUCCESS host=$HOST platform=linux hostname=$HOSTNAME_VALUE files=$LOCKED_FILES directory=$IMPACT_DIR"


        else

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Impact simulation failed on Linux host $HOST"

            ground_truth \
                "IMPACT_FAILED host=$HOST platform=linux"

        fi


    # ========================================================
    # WINDOWS
    # ========================================================

    elif [[ "$PLATFORM" == "windows" ]]; then


        if [[ -z "$RDP_PASSWORD" ]]; then

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Windows password unavailable for $HOST"

            ground_truth \
                "IMPACT_FAILED host=$HOST platform=windows reason=missing_credentials"

            continue
        fi


        if [[ $PYWINRM_AVAILABLE -ne 1 ]]; then

            SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

            log "[SKIPPED] Python pywinrm is not installed."

            ground_truth \
                "IMPACT_SKIPPED host=$HOST platform=windows reason=pywinrm_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Find WinRM endpoint
        # ----------------------------------------------------

        WINRM_PORT=""
        WINRM_SCHEME=""


        if tcp_open "$HOST" "$WINRM_HTTP_PORT"; then

            WINRM_PORT="$WINRM_HTTP_PORT"
            WINRM_SCHEME="http"


        elif tcp_open "$HOST" "$WINRM_HTTPS_PORT"; then

            WINRM_PORT="$WINRM_HTTPS_PORT"
            WINRM_SCHEME="https"


        else

            SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

            log "[SKIPPED] No reachable WinRM service on $HOST"

            ground_truth \
                "IMPACT_SKIPPED host=$HOST platform=windows reason=winrm_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Controlled Windows ransomware indicator simulation.
        #
        # Everything is created underneath:
        #
        # C:\NordicIncident\<INCIDENT-ID>\impact\
        #
        # Only those newly created files are renamed.
        # ----------------------------------------------------

        WINDOWS_RESULT="$(
            NORDIC_WINRM_PASSWORD="$RDP_PASSWORD" \
            python3 - \
                "$HOST" \
                "$WINRM_PORT" \
                "$WINRM_SCHEME" \
                "$ACCESS_USER" \
                "$INCIDENT_ID" <<'PY'

import os
import sys

import winrm


host = sys.argv[1]
port = int(sys.argv[2])
scheme = sys.argv[3]
username = sys.argv[4]
incident_id = sys.argv[5]

password = os.environ[
    "NORDIC_WINRM_PASSWORD"
]


endpoint = (
    f"{scheme}://"
    f"{host}:"
    f"{port}/wsman"
)


session = winrm.Session(
    endpoint,
    auth=(
        username,
        password
    ),
    transport="ntlm",
    server_cert_validation="ignore",
)


safe_incident = (
    incident_id
    .replace("'", "")
    .replace('"', "")
)


powershell = rf'''
$ErrorActionPreference = "Stop"

$IncidentId = '{safe_incident}'

$ImpactDir = Join-Path `
    "C:\NordicIncident" `
    $IncidentId

$ImpactDir = Join-Path `
    $ImpactDir `
    "impact"

$DataDir = Join-Path `
    $ImpactDir `
    "company-data"


# ============================================================
# CREATE ISOLATED DIRECTORY TREE
# ============================================================

$Directories = @(
    "Finance",
    "HR",
    "Production",
    "Webshop",
    "Management"
)


foreach ($Directory in $Directories) {{

    New-Item `
        -ItemType Directory `
        -Path (
            Join-Path `
                $DataDir `
                $Directory
        ) `
        -Force `
        | Out-Null
}}


# ============================================================
# SYNTHETIC COMPANY FILES
# ============================================================

@"
Invoice,Customer,Amount
INV-2026-1001,Nordic Customer 01,12500
INV-2026-1002,Nordic Customer 02,8700
INV-2026-1003,Nordic Customer 03,19300
"@ |
Set-Content `
    -LiteralPath (
        Join-Path `
            $DataDir `
            "Finance\invoices.csv"
    ) `
    -Encoding UTF8


@"
EmployeeID,Department,Status
EMP-1001,Production,Active
EMP-1002,IT,Active
EMP-1003,Sales,Active
"@ |
Set-Content `
    -LiteralPath (
        Join-Path `
            $DataDir `
            "HR\employees.csv"
    ) `
    -Encoding UTF8


@"
Nordic Manufacturing
Production Schedule

Line 1: Running
Line 2: Running
Line 3: Maintenance scheduled
"@ |
Set-Content `
    -LiteralPath (
        Join-Path `
            $DataDir `
            "Production\production-plan.txt"
    ) `
    -Encoding UTF8


@"
OrderID,Status
ORD-5001,Processing
ORD-5002,Ready
ORD-5003,Processing
"@ |
Set-Content `
    -LiteralPath (
        Join-Path `
            $DataDir `
            "Webshop\orders.csv"
    ) `
    -Encoding UTF8


@"
NORDIC MANUFACTURING A/S

CONFIDENTIAL

Synthetic H3 CyberLab training document.
"@ |
Set-Content `
    -LiteralPath (
        Join-Path `
            $DataDir `
            "Management\business-plan.txt"
    ) `
    -Encoding UTF8


1..10 | ForEach-Object {{

    $Document = Join-Path `
        $DataDir `
        (
            "Management\document-" +
            $_ +
            ".txt"
        )


    (
        "Nordic Manufacturing synthetic training document " +
        $_
    ) |
    Set-Content `
        -LiteralPath $Document `
        -Encoding UTF8
}}


# ============================================================
# COUNT BEFORE IMPACT
# ============================================================

$Files = @(
    Get-ChildItem `
        -LiteralPath $DataDir `
        -File `
        -Recurse
)


$Before = $Files.Count


# ============================================================
# CONTROLLED IMPACT
#
# Rename ONLY the files we just enumerated underneath DataDir.
#
# No encryption is performed.
# ============================================================

foreach ($File in $Files) {{

    Rename-Item `
        -LiteralPath $File.FullName `
        -NewName (
            $File.Name +
            ".locked"
        )
}}


# ============================================================
# RECOVERY NOTE
# ============================================================

$RecoveryNote = Join-Path `
    $ImpactDir `
    "README_RECOVER_FILES.txt"


@"
============================================================
YOUR FILES ARE UNAVAILABLE
============================================================

Nordic Manufacturing A/S
H3 CyberLab Incident Simulation

Incident:
$IncidentId

Multiple company files are currently unavailable.

This is a CONTROLLED TRAINING SIMULATION.

No real encryption has been performed.
No real user data has been modified.

Contact the Incident Response Team.

============================================================
"@ |
Set-Content `
    -LiteralPath $RecoveryNote `
    -Encoding UTF8


# ============================================================
# RESULT
# ============================================================

$Locked = @(
    Get-ChildItem `
        -LiteralPath $DataDir `
        -File `
        -Recurse `
        -Filter "*.locked"
).Count


Write-Output (
    "NORDIC_IMPACT_OK|" +
    $ImpactDir +
    "|" +
    $Before +
    "|" +
    $Locked +
    "|" +
    $env:COMPUTERNAME
)
'''


result = session.run_ps(
    powershell
)


stdout = result.std_out.decode(
    "utf-8",
    errors="replace"
)

stderr = result.std_err.decode(
    "utf-8",
    errors="replace"
)


if stdout:
    print(
        stdout,
        end=""
    )


if stderr:
    print(
        stderr,
        file=sys.stderr,
        end=""
    )


sys.exit(
    0 if result.status_code == 0 else 1
)

PY
        )"


        COMMAND_RESULT=$?


        if [[ $COMMAND_RESULT -eq 0 ]] &&
           grep -q '^NORDIC_IMPACT_OK|' <<< "$WINDOWS_RESULT"; then


            RESULT_LINE="$(
                printf '%s\n' "$WINDOWS_RESULT" |
                grep '^NORDIC_IMPACT_OK|' |
                tail -n 1
            )"


            IFS='|' read -r \
                STATUS \
                IMPACT_DIR \
                ORIGINAL_FILES \
                LOCKED_FILES \
                HOSTNAME_VALUE \
                <<< "$RESULT_LINE"


            SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
            WINDOWS_SUCCESS=$(( WINDOWS_SUCCESS + 1 ))


            log "[+] Impact simulation completed on $HOST"
            log "    Platform: Windows"
            log "    Hostname: $HOSTNAME_VALUE"
            log "    Impact directory: $IMPACT_DIR"
            log "    Files affected: $LOCKED_FILES"


            printf '%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "windows" \
                "$HOSTNAME_VALUE" \
                "$IMPACT_DIR" \
                "$ORIGINAL_FILES" \
                "$LOCKED_FILES" \
                >> "$TMP_RESULTS"


            ground_truth \
                "IMPACT_SUCCESS host=$HOST platform=windows hostname=$HOSTNAME_VALUE files=$LOCKED_FILES directory=$IMPACT_DIR"


        else

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Impact simulation failed on Windows host $HOST"

            ground_truth \
                "IMPACT_FAILED host=$HOST platform=windows"

        fi


    # ========================================================
    # UNKNOWN PLATFORM
    # ========================================================

    else

        SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

        log "[SKIPPED] Unknown platform for $HOST: $PLATFORM"

        ground_truth \
            "IMPACT_SKIPPED host=$HOST reason=unknown_platform"

    fi

done


# ============================================================
# CREATE impact.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$IMPACT_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone


source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]

hosts = []


with open(
    source_file,
    encoding="utf-8"
) as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue


        (
            ip,
            platform,
            hostname,
            impact_dir,
            original_files,
            locked_files,
        ) = line.split("|", 5)


        hosts.append(
            {
                "ip": ip,
                "platform": platform,
                "hostname": hostname,
                "impacted": True,
                "impact_type": "ransomware-simulation",
                "directory": impact_dir,
                "original_files": int(original_files),
                "locked_files": int(locked_files),
                "real_encryption": False,
            }
        )


data = {
    "incident_id": incident_id,
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": len(hosts),
    "hosts": hosts,
}


with open(
    output_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        data,
        f,
        indent=2
    )

PY


rm -f "$TMP_RESULTS"


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 07 COMPLETED"
echo "============================================================"
echo

echo "Compromised hosts:"
echo "  ${#COMPROMISED[@]}"

echo

echo "Hosts impacted:"
echo "  $SUCCESS_COUNT"

echo

echo "Linux impacted:"
echo "  $LINUX_SUCCESS"

echo

echo "Windows impacted:"
echo "  $WINDOWS_SUCCESS"

echo

echo "Failed:"
echo "  $FAILED_COUNT"

echo

echo "Skipped:"
echo "  $SKIPPED_COUNT"

echo

echo "Impact inventory:"
echo "  $IMPACT_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE impacted=$SUCCESS_COUNT linux_impacted=$LINUX_SUCCESS windows_impacted=$WINDOWS_SUCCESS failed=$FAILED_COUNT skipped=$SKIPPED_COUNT"


exit 0