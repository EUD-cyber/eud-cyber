#!/usr/bin/env bash

set -u


# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 05 - Data Staging
#
# Linux:
#   Synthetic data under:
#   /tmp/.nordic-<INCIDENT-ID>/
#
# Windows:
#   Synthetic data under:
#   C:\NordicIncident\<INCIDENT-ID>\staging\
#
# Only hosts successfully compromised during Phase 03 are
# processed.
#
# No real user/business data is collected.
# ============================================================

# ============================================================
# ATTACK METADATA
# ============================================================

ATTACK_ID="05"
ATTACK_NAME="Data Staging"
ATTACK_ALIAS="staging"
ATTACK_STANDALONE="true"
ATTACK_PARAMETERS="target,port,protocol,username,password"
ATTACK_CAMPAIGN_STATE="compromised-hosts"

ATTACK_MITRE_TACTIC="Collection"
ATTACK_MITRE_TECHNIQUES="T1074"

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

# ============================================================
# EXECUTION MODE
# ============================================================

RUN_MODE="${MRNOBODY_RUN_MODE:-campaign}"

MANUAL_TARGET="${MRNOBODY_TARGET:-}"
MANUAL_PORT="${MRNOBODY_PORT:-}"
MANUAL_PROTOCOL="${MRNOBODY_PROTOCOL:-}"
MANUAL_USERNAME="${MRNOBODY_USERNAME:-}"
MANUAL_PASSWORD="${MRNOBODY_PASSWORD:-}"

WINRM_HTTP_PORT="${NORDIC_WINRM_HTTP_PORT:-${NORDIC_DEFAULT_WINRM_HTTP_PORT:-5985}}"
WINRM_HTTPS_PORT="${NORDIC_WINRM_HTTPS_PORT:-${NORDIC_DEFAULT_WINRM_HTTPS_PORT:-5986}}"

COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-05-staging.log"

STAGING_STATE="$NORDIC_STATE_DIR/staged-data.json"


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

    printf '%s INCIDENT=%s PHASE=05 %s\n' \
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
# WINDOWS WINRM SUPPORT
# ============================================================

PYWINRM_AVAILABLE=0

if python3 -c "import winrm" >/dev/null 2>&1; then
    PYWINRM_AVAILABLE=1
fi


# ============================================================
# VALIDATION
# ============================================================

if [[ "$RUN_MODE" == "campaign" ]]; then

    if [[ ! -f "$COMPROMISED_STATE" ]]; then

        echo "[ERROR] Missing compromised host inventory:"
        echo "$COMPROMISED_STATE"
        echo
        echo "Run Phase 03 first."

        exit 1
    fi

elif [[ "$RUN_MODE" == "standalone" ]]; then

    if [[ -z "$MANUAL_TARGET" ]]; then

        echo "[ERROR] Standalone mode requires --target"
        exit 1
    fi

else

    echo "[ERROR] Unknown run mode: $RUN_MODE"
    exit 1

fi


# ============================================================
# LOAD COMPROMISED HOSTS
#
# Format:
#
# IP|PLATFORM|ACCESS|PORT|USER|PASSWORD
#
# Old SSH-only state remains supported.
# ============================================================

# ============================================================
# LOAD COMPROMISED HOSTS
#
# Format:
#
# IP|PLATFORM|ACCESS|PORT|USER|PASSWORD
#
# Campaign:
#   Loaded from compromised host inventory.
#
# Standalone:
#   Built from MRNOBODY_* parameters.
# ============================================================

COMPROMISED=()

if [[ "$RUN_MODE" == "campaign" ]]; then

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

    # --------------------------------------------------------
    # Backwards compatibility
    # --------------------------------------------------------

    if not platform:

        if access == "rdp":
            platform = "windows"
        else:
            platform = "linux"

    # --------------------------------------------------------
    # Linux
    # --------------------------------------------------------

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

        password = (
            host.get("ssh_password")
            or host.get("password")
            or ""
        )

        print(
            f"{ip}|linux|ssh|{port}|{user}|{password}"
        )

    # --------------------------------------------------------
    # Windows
    # --------------------------------------------------------

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

        password = (
            host.get("rdp_password")
            or host.get("password")
            or ""
        )

        print(
            f"{ip}|windows|rdp|{port}|{user}|{password}"
        )

    # --------------------------------------------------------
    # FreeBSD / OPNsense
    # --------------------------------------------------------

    elif platform == "freebsd":

        port = host.get(
            "ssh_port",
            22
        )

        user = (
            host.get("ssh_username")
            or host.get("ssh_user")
            or "root"
        )

        password = (
            host.get("ssh_password")
            or host.get("password")
            or ""
        )

        print(
            f"{ip}|freebsd|ssh|{port}|{user}|{password}"
        )

PY

    )

elif [[ "$RUN_MODE" == "standalone" ]]; then

    case "${MANUAL_PROTOCOL,,}" in

        ssh|"")
            PLATFORM="linux"
            ACCESS="ssh"
            ACCESS_PORT="${MANUAL_PORT:-22}"
            ACCESS_USER="${MANUAL_USERNAME:-ubuntu}"
            ;;

        winrm|winrm-http)
            PLATFORM="windows"
            ACCESS="winrm"
            ACCESS_PORT="${MANUAL_PORT:-5985}"
            ACCESS_USER="${MANUAL_USERNAME:-Administrator}"
            ;;

        winrm-https)
            PLATFORM="windows"
            ACCESS="winrm"
            ACCESS_PORT="${MANUAL_PORT:-5986}"
            ACCESS_USER="${MANUAL_USERNAME:-Administrator}"
            ;;

        *)
            echo "[ERROR] Unsupported standalone protocol: ${MANUAL_PROTOCOL}"
            exit 1
            ;;

    esac

    COMPROMISED=(
        "${MANUAL_TARGET}|${PLATFORM}|${ACCESS}|${ACCESS_PORT}|${ACCESS_USER}|${MANUAL_PASSWORD}"
    )

fi


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 05 - DATA STAGING"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Compromised hosts: ${#COMPROMISED[@]}"

echo


# ============================================================
# NO COMPROMISED HOSTS
# ============================================================

if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."
    log "[*] Phase 05 has nothing to stage."

    python3 - "$STAGING_STATE" "$INCIDENT_ID" <<'PY'
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
        "PHASE_COMPLETE staged_hosts=0"

    exit 0
fi


# ============================================================
# TEMP RESULT FILE
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.staging.tmp"

: > "$TMP_RESULTS"

STAGED_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

LINUX_STAGED=0
WINDOWS_STAGED=0
FREEBSD_SKIPPED=0


# ============================================================
# PROCESS COMPROMISED HOSTS
# ============================================================

for RECORD in "${COMPROMISED[@]}"; do

    IFS='|' read -r \
        HOST \
        PLATFORM \
        ACCESS \
        ACCESS_PORT \
        ACCESS_USER \
        ACCESS_PASSWORD \
        <<< "$RECORD"

    if [[ -z "$ACCESS_PASSWORD" ]]; then

    if [[ "$RUN_MODE" == "standalone" ]]; then

        FAILED_COUNT=$(( FAILED_COUNT + 1 ))

        log "[WARNING] Password unavailable for standalone target $HOST"

        ground_truth \
            "STAGING_FAILED host=$HOST platform=$PLATFORM reason=missing_credentials"

        continue

    fi

    if [[ "$PLATFORM" == "linux" ]]; then
        ACCESS_PASSWORD="$SSH_PASSWORD"

    elif [[ "$PLATFORM" == "windows" ]]; then
        ACCESS_PASSWORD="$RDP_PASSWORD"
    fi

fi

    echo
    echo "------------------------------------------------------------"
    echo " Compromised host: $HOST"
    echo " Platform:         $PLATFORM"
    echo "------------------------------------------------------------"
    echo


    log "[*] Starting staging on $HOST ($PLATFORM)"

    ground_truth \
        "STAGING_START host=$HOST platform=$PLATFORM user=$ACCESS_USER"


    # ========================================================
    # LINUX STAGING
    # ========================================================

    if [[ "$PLATFORM" == "linux" ]]; then


        if [[ -z "$ACCESS_PASSWORD" ]]; then

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] SSH password unavailable for $HOST"

            ground_truth \
                "STAGING_FAILED host=$HOST platform=linux reason=missing_credentials"

            continue
        fi


        REMOTE_DIR="/tmp/.nordic-${INCIDENT_ID}"

        REMOTE_FILE="${REMOTE_DIR}/nordic-data-${INCIDENT_ID}.txt"


        read -r -d '' REMOTE_SCRIPT <<'REMOTE_EOF' || true

set -e

INCIDENT_ID="$1"
REMOTE_DIR="$2"
REMOTE_FILE="$3"

mkdir -p "$REMOTE_DIR"

chmod 700 "$REMOTE_DIR"

HOSTNAME_VALUE="$(
    hostname 2>/dev/null ||
    echo unknown
)"


cat > "$REMOTE_FILE" <<EOF
============================================================
NORDIC MANUFACTURING A/S
SIMULATED INCIDENT DATA
============================================================

Incident ID:
$INCIDENT_ID

Source host:
$HOSTNAME_VALUE

Classification:
CONFIDENTIAL

Dataset:
Synthetic CyberLab Training Data

CUSTOMER_ID,NAME,EMAIL,ORDER_VALUE
NM-1001,Anna Jensen,anna.jensen@example.invalid,12450
NM-1002,Lars Hansen,lars.hansen@example.invalid,8995
NM-1003,Mette Nielsen,mette.nielsen@example.invalid,17400
NM-1004,Peter Sørensen,peter.sorensen@example.invalid,6300
NM-1005,Sofie Larsen,sofie.larsen@example.invalid,22150

------------------------------------------------------------
INTERNAL SYSTEM INFORMATION
------------------------------------------------------------

ERP-System: NordicERP
Production-System: NordicMES
Webshop: NordicShop
Environment: CyberLab

------------------------------------------------------------
TRAINING NOTICE
------------------------------------------------------------

This file contains synthetic data generated for the
Nordic Manufacturing H3 cybersecurity training campaign.

No real customer or employee data is contained in this file.
EOF


chmod 600 "$REMOTE_FILE"


SIZE="$(
    wc -c < "$REMOTE_FILE"
)"


HASH=""

if command -v sha256sum >/dev/null 2>&1; then

    HASH="$(
        sha256sum "$REMOTE_FILE" |
        awk '{print $1}'
    )"

fi


printf 'NORDIC_STAGING_OK|%s|%s|%s\n' \
    "$REMOTE_FILE" \
    "$SIZE" \
    "$HASH"

REMOTE_EOF


        RESULT="$(
            sshpass -p "$ACCESS_PASSWORD" \
                ssh \
                    -p "$ACCESS_PORT" \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
                    -o PreferredAuthentications=password \
                    -o PubkeyAuthentication=no \
                    -o NumberOfPasswordPrompts=1 \
                    "$ACCESS_USER@$HOST" \
                    bash -s -- \
                        "$INCIDENT_ID" \
                        "$REMOTE_DIR" \
                        "$REMOTE_FILE" \
                    <<< "$REMOTE_SCRIPT" \
                    2>/dev/null
        )"

        SSH_RESULT=$?


        if [[ $SSH_RESULT -eq 0 ]] &&
           grep -q '^NORDIC_STAGING_OK|' <<< "$RESULT"; then


            STAGING_RESULT="$(
                printf '%s\n' "$RESULT" |
                grep '^NORDIC_STAGING_OK|' |
                tail -n 1
            )"


            IFS='|' read -r \
                STATUS \
                STAGED_FILE \
                FILE_SIZE \
                FILE_HASH \
                <<< "$STAGING_RESULT"


            STAGED_COUNT=$(( STAGED_COUNT + 1 ))
            LINUX_STAGED=$(( LINUX_STAGED + 1 ))


            log "[+] Data staged successfully on $HOST"
            log "    Platform: Linux"
            log "    File: $STAGED_FILE"
            log "    Size: $FILE_SIZE bytes"

            if [[ -n "$FILE_HASH" ]]; then

                log "    SHA256: $FILE_HASH"

            fi


            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "linux" \
                "ssh" \
                "$ACCESS_PORT" \
                "$ACCESS_USER" \
                "$STAGED_FILE" \
                "$FILE_SIZE" \
                "$FILE_HASH" \
                >> "$TMP_RESULTS"


            ground_truth \
                "STAGING_SUCCESS host=$HOST platform=linux file=$STAGED_FILE size=$FILE_SIZE sha256=$FILE_HASH"


        else

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Data staging failed on Linux host $HOST"

            ground_truth \
                "STAGING_FAILED host=$HOST platform=linux"

        fi


    # ========================================================
    # WINDOWS STAGING
    # ========================================================

    elif [[ "$PLATFORM" == "windows" ]]; then


        if [[ -z "$ACCESS_PASSWORD" ]]; then

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Windows password unavailable for $HOST"

            ground_truth \
                "STAGING_FAILED host=$HOST platform=windows reason=missing_credentials"

            continue
        fi


                # ----------------------------------------------------
        # Determine WinRM transport
        # ----------------------------------------------------

        WINRM_PORT=""
        WINRM_SCHEME=""

        if [[ "$RUN_MODE" == "standalone" ]]; then

            if [[ "$ACCESS" != "winrm" ]]; then

                SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

                log "[SKIPPED] Unsupported Windows access method for staging on $HOST: $ACCESS"

                ground_truth \
                    "STAGING_SKIPPED host=$HOST platform=windows reason=unsupported_access access=$ACCESS"

                continue
            fi

            WINRM_PORT="$ACCESS_PORT"

            case "${MANUAL_PROTOCOL,,}" in

                winrm-https)
                    WINRM_SCHEME="https"
                    ;;

                winrm|winrm-http)
                    WINRM_SCHEME="http"
                    ;;

                *)
                    SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

                    log "[SKIPPED] Unsupported WinRM protocol for $HOST: ${MANUAL_PROTOCOL}"

                    ground_truth \
                        "STAGING_SKIPPED host=$HOST platform=windows reason=unsupported_protocol protocol=${MANUAL_PROTOCOL}"

                    continue
                    ;;

            esac

            if ! tcp_open "$HOST" "$WINRM_PORT"; then

                SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

                log "[SKIPPED] No reachable WinRM service on $HOST port $WINRM_PORT"

                ground_truth \
                    "STAGING_SKIPPED host=$HOST platform=windows reason=winrm_unavailable port=$WINRM_PORT"

                continue
            fi

        else

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
                    "STAGING_SKIPPED host=$HOST platform=windows reason=winrm_unavailable"

                continue
            fi

        fi


        if [[ $PYWINRM_AVAILABLE -ne 1 ]]; then

            SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

            log "[SKIPPED] Python pywinrm is not installed."

            ground_truth \
                "STAGING_SKIPPED host=$HOST platform=windows reason=pywinrm_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Execute PowerShell staging
        #
        # Only synthetic files under C:\NordicIncident\
        # ----------------------------------------------------

        WINDOWS_RESULT="$(
            NORDIC_WINRM_PASSWORD="$ACCESS_PASSWORD" \
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

$BaseDir = Join-Path `
    "C:\NordicIncident" `
    $IncidentId

$StagingDir = Join-Path `
    $BaseDir `
    "staging"

$StagedFile = Join-Path `
    $StagingDir `
    ("nordic-data-" + $IncidentId + ".txt")


New-Item `
    -ItemType Directory `
    -Path $StagingDir `
    -Force `
    | Out-Null


$HostnameValue = $env:COMPUTERNAME


$Content = @"
============================================================
NORDIC MANUFACTURING A/S
SIMULATED INCIDENT DATA
============================================================

Incident ID:
$IncidentId

Source host:
$HostnameValue

Classification:
CONFIDENTIAL

Dataset:
Synthetic CyberLab Training Data

CUSTOMER_ID,NAME,EMAIL,ORDER_VALUE
NM-1001,Anna Jensen,anna.jensen@example.invalid,12450
NM-1002,Lars Hansen,lars.hansen@example.invalid,8995
NM-1003,Mette Nielsen,mette.nielsen@example.invalid,17400
NM-1004,Peter Sørensen,peter.sorensen@example.invalid,6300
NM-1005,Sofie Larsen,sofie.larsen@example.invalid,22150

------------------------------------------------------------
INTERNAL SYSTEM INFORMATION
------------------------------------------------------------

ERP-System: NordicERP
Production-System: NordicMES
Webshop: NordicShop
Environment: CyberLab

------------------------------------------------------------
TRAINING NOTICE
------------------------------------------------------------

This file contains synthetic data generated for the
Nordic Manufacturing H3 cybersecurity training campaign.

No real customer or employee data is contained in this file.
"@


Set-Content `
    -Path $StagedFile `
    -Value $Content `
    -Encoding UTF8


$FileInfo = Get-Item `
    -LiteralPath $StagedFile


$Hash = (
    Get-FileHash `
        -LiteralPath $StagedFile `
        -Algorithm SHA256
).Hash.ToLower()


Write-Output (
    "NORDIC_STAGING_OK|" +
    $StagedFile +
    "|" +
    $FileInfo.Length +
    "|" +
    $Hash
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

        WINDOWS_STATUS=$?


        if [[ $WINDOWS_STATUS -eq 0 ]] &&
           grep -q '^NORDIC_STAGING_OK|' <<< "$WINDOWS_RESULT"; then


            STAGING_RESULT="$(
                printf '%s\n' "$WINDOWS_RESULT" |
                grep '^NORDIC_STAGING_OK|' |
                tail -n 1
            )"


            IFS='|' read -r \
                STATUS \
                STAGED_FILE \
                FILE_SIZE \
                FILE_HASH \
                <<< "$STAGING_RESULT"


            STAGED_COUNT=$(( STAGED_COUNT + 1 ))
            WINDOWS_STAGED=$(( WINDOWS_STAGED + 1 ))


            log "[+] Data staged successfully on $HOST"
            log "    Platform: Windows"
            log "    File: $STAGED_FILE"
            log "    Size: $FILE_SIZE bytes"

            if [[ -n "$FILE_HASH" ]]; then

                log "    SHA256: $FILE_HASH"

            fi


            printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "windows" \
                "winrm" \
                "$WINRM_PORT" \
                "$ACCESS_USER" \
                "$STAGED_FILE" \
                "$FILE_SIZE" \
                "$FILE_HASH" \
                >> "$TMP_RESULTS"


            ground_truth \
                "STAGING_SUCCESS host=$HOST platform=windows file=$STAGED_FILE size=$FILE_SIZE sha256=$FILE_HASH"


        else

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Data staging failed on Windows host $HOST"

            ground_truth \
                "STAGING_FAILED host=$HOST platform=windows"

        fi

        elif [[ "$PLATFORM" == "freebsd" ]]; then

            # FreeBSD / OPNsense
            FREEBSD_SKIPPED=$(( FREEBSD_SKIPPED + 1 ))
            SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

            log "[SKIPPED] FreeBSD host $HOST is authenticated, but Linux staging payload is not applicable."

            ground_truth \
                "STAGING_SKIPPED host=$HOST platform=freebsd reason=unsupported_payload"

            continue



    # ========================================================
    # UNKNOWN PLATFORM
    # ========================================================

    else

        SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

        log "[SKIPPED] Unknown platform for $HOST: $PLATFORM"

        ground_truth \
            "STAGING_SKIPPED host=$HOST reason=unknown_platform"

    fi

done


# ============================================================
# CREATE staged-data.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$STAGING_STATE" \
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
    "r",
    encoding="utf-8"
) as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue

        (
            ip,
            platform,
            access,
            port,
            user,
            path,
            size,
            sha256,
        ) = line.split("|", 7)


        entry = {
            "ip": ip,
            "platform": platform,
            "access": access,
            "staged": True,
            "file": path,
            "size": int(size),
            "sha256": sha256,
            "data_type": "synthetic-training-data",
        }


        if platform == "linux":

            entry["ssh_port"] = int(port)
            entry["ssh_user"] = user
            entry["ssh_username"] = user


        elif platform == "windows":

            entry["winrm_port"] = int(port)
            entry["rdp_user"] = user
            entry["rdp_username"] = user


        hosts.append(
            entry
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
echo " PHASE 05 COMPLETED"
echo "============================================================"
echo

echo "Compromised hosts:"
echo "  ${#COMPROMISED[@]}"

echo

echo "Successfully staged:"
echo "  $STAGED_COUNT"

echo

echo "Linux staged:"
echo "  $LINUX_STAGED"

echo

echo "Windows staged:"
echo "  $WINDOWS_STAGED"

echo

echo "FreeBSD skipped:"
echo "  $FREEBSD_SKIPPED"

echo

echo "Failed:"
echo "  $FAILED_COUNT"

echo

echo "Skipped:"
echo "  $SKIPPED_COUNT"

echo

echo "Staging inventory:"
echo "  $STAGING_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE compromised=${#COMPROMISED[@]} staged=$STAGED_COUNT linux_staged=$LINUX_STAGED windows_staged=$WINDOWS_STAGED freebsd_skipped=$FREEBSD_SKIPPED failed=$FAILED_COUNT skipped=$SKIPPED_COUNT"

exit 0