#!/usr/bin/env bash

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 01 - Dynamic Network Discovery
#
# Discovers:
#   - Directly connected RFC1918 networks
#   - Active hosts on those networks
#
# Does NOT:
#   - Scan public/WAN networks
#   - Scan explicitly excluded networks
#   - Scan ignored interfaces
#   - Perform service discovery
#
# Output:
#   state/networks.json
#   state/discovered-hosts.json
#
# ============================================================

# ============================================================
# MRNOBODY ATTACK METADATA
# ============================================================

# ATTACK_ID="01"
# ATTACK_NAME="Discovery"
# ATTACK_ALIAS="discovery"
# ATTACK_STANDALONE="true"
# ATTACK_PARAMETERS="subnet"
# ATTACK_CAMPAIGN_STATE="networks,discovered-hosts"

# MITRE_TACTIC="Discovery"
# MITRE_TECHNIQUES="T1018,T1049"

set -u


# ============================================================
# BASE CONFIGURATION
# ============================================================

BASE_DIR="/opt/nordic-attack"

DEFAULTS_FILE="${BASE_DIR}/config/defaults.conf"

if [[ ! -f "$DEFAULTS_FILE" ]]; then
    echo "[ERROR] Missing configuration: $DEFAULTS_FILE"
    exit 1
fi

# shellcheck disable=SC1090
source "$DEFAULTS_FILE"


mkdir -p \
    "$NORDIC_STATE_DIR" \
    "$NORDIC_LOG_DIR"


INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

export NORDIC_INCIDENT_ID="$INCIDENT_ID"

# ============================================================
# DISCOVERY INPUT
# ============================================================

AUTO_DISCOVERY="${MRNOBODY_AUTO:-1}"
MANUAL_SUBNETS="${MRNOBODY_SUBNET:-}"

# ============================================================
# EXECUTION MODE
# ============================================================

RUN_MODE="${MRNOBODY_RUN_MODE:-campaign}"
MANUAL_SUBNETS="${MRNOBODY_SUBNET:-}"

# ============================================================
# LOGGING
# ============================================================

log() {

    local message="$1"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message"
}


ground_truth() {

    local message="$1"

    printf '%s | %s | PHASE01 | %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" \
        "$INCIDENT_ID" \
        "$message" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


# ============================================================
# REQUIREMENTS
# ============================================================

for command in ip python3 nmap; do

    if ! command -v "$command" >/dev/null 2>&1; then

        log "[ERROR] Required command not found: $command"

        exit 1
    fi

done


# ============================================================
# TEMP FILES
# ============================================================

TMP_DIR="$(mktemp -d)"

NETWORK_TMP="${TMP_DIR}/networks.txt"
HOST_TMP="${TMP_DIR}/hosts.txt"

touch "$NETWORK_TMP"
touch "$HOST_TMP"


cleanup() {

    rm -rf "$TMP_DIR"
}

trap cleanup EXIT


# ============================================================
# HELPERS
# ============================================================

trim() {

    local value="$1"

    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    printf '%s' "$value"
}


canonical_network() {

    local cidr="$1"

    python3 - "$cidr" <<'PY'
import ipaddress
import sys

try:
    interface = ipaddress.ip_interface(sys.argv[1])
    print(interface.network)

except ValueError:
    sys.exit(1)
PY
}


is_private_network() {

    local cidr="$1"

    python3 - "$cidr" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(
        sys.argv[1],
        strict=False
    )

except ValueError:
    sys.exit(1)

private_ranges = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

if any(network.subnet_of(private) for private in private_ranges):
    sys.exit(0)

sys.exit(1)
PY
}


network_prefix() {

    local cidr="$1"

    printf '%s\n' "${cidr##*/}"
}


interface_is_ignored() {

    local interface="$1"

    local configured="${NORDIC_DISCOVERY_IGNORE_INTERFACES:-lo}"

    local entry

    IFS=',' read -ra entries <<< "$configured"

    for entry in "${entries[@]}"; do

        entry="$(trim "$entry")"

        [[ -z "$entry" ]] && continue

        if [[ "$interface" == "$entry" ]]; then
            return 0
        fi

    done

    return 1
}


network_is_excluded() {

    local candidate="$1"

    local configured="${NORDIC_DISCOVERY_EXCLUDE_NETWORKS:-}"

    [[ -z "$configured" ]] && return 1

    local entry
    local canonical

    IFS=',' read -ra entries <<< "$configured"

    for entry in "${entries[@]}"; do

        entry="$(trim "$entry")"

        [[ -z "$entry" ]] && continue

        canonical="$(canonical_network "$entry" 2>/dev/null || true)"

        if [[ -z "$canonical" ]]; then

            log "[WARN] Invalid excluded network ignored: $entry"

            continue
        fi


        if [[ "$candidate" == "$canonical" ]]; then
            return 0
        fi

    done

    return 1
}


# ============================================================
# START
# ============================================================

echo
echo "============================================================"
echo " PHASE 01 - DYNAMIC NETWORK DISCOVERY"
echo "============================================================"
echo

log "[INFO] Incident ID: $INCIDENT_ID"

log "[INFO] Discovering directly connected IPv4 networks..."

ground_truth "Dynamic network discovery started"


# ============================================================
# LOCAL INTERFACE INFORMATION
# ============================================================

declare -A LOCAL_IPS

while read -r line; do

    [[ -z "$line" ]] && continue

    interface="$(awk '{print $2}' <<< "$line")"

    address="$(awk '{print $4}' <<< "$line")"

    ip_address="${address%%/*}"

    LOCAL_IPS["$ip_address"]=1

done < <(
    ip -o -4 addr show scope global
)


# ============================================================
# DISCOVER CONNECTED NETWORKS
# ============================================================

if [[ "$AUTO_DISCOVERY" == "1" ]]; then

    while read -r line; do

        [[ -z "$line" ]] && continue

        interface="$(awk '{print $2}' <<< "$line")"
        address="$(awk '{print $4}' <<< "$line")"

        if interface_is_ignored "$interface"; then
            log "[SKIP] Interface ignored: $interface"
            continue
        fi

        network="$(canonical_network "$address" 2>/dev/null || true)"

        if [[ -z "$network" ]]; then
            log "[SKIP] Unable to determine network for $address"
            continue
        fi

        if [[ "${NORDIC_DISCOVERY_PRIVATE_ONLY:-1}" == "1" ]]; then

            if ! is_private_network "$network"; then
                log "[SKIP] Non-private network: $network ($interface)"
                ground_truth \
                    "Skipped non-private network=$network interface=$interface"
                continue
            fi

        fi

        prefix="$(network_prefix "$network")"

        if (( prefix < NORDIC_DISCOVERY_MIN_PREFIX )); then
            log "[SKIP] Network too large: $network"
            ground_truth \
                "Skipped oversized network=$network interface=$interface"
            continue
        fi

        if network_is_excluded "$network"; then
            log "[SKIP] Excluded network: $network ($interface)"
            ground_truth \
                "Excluded network=$network interface=$interface"
            continue
        fi

        if grep -Fqx \
            "${network}|${interface}" \
            "$NETWORK_TMP"; then
            continue
        fi

        printf '%s|%s\n' \
            "$network" \
            "$interface" \
            >> "$NETWORK_TMP"

        log "[NETWORK] $network via $interface"

        ground_truth \
            "Discovery network=$network interface=$interface"

    done < <(
        ip -o -4 addr show scope global
    )

else

    log "[INFO] Automatic interface discovery disabled."

fi

# ============================================================
# ADD MANUAL SUBNETS
# ============================================================

if [[ -n "$MANUAL_SUBNETS" ]]; then

    IFS=',' read -ra SUBNET_LIST <<< "$MANUAL_SUBNETS"

    for entry in "${SUBNET_LIST[@]}"; do

        entry="$(trim "$entry")"

        [[ -z "$entry" ]] && continue

        network="$(canonical_network "$entry" 2>/dev/null || true)"

        if [[ -z "$network" ]]; then
            log "[WARN] Invalid manual subnet ignored: $entry"
            ground_truth \
                "Invalid manual subnet=$entry"
            continue
        fi

        if [[ "${NORDIC_DISCOVERY_PRIVATE_ONLY:-1}" == "1" ]]; then

            if ! is_private_network "$network"; then
                log "[SKIP] Non-private manual subnet: $network"
                ground_truth \
                    "Skipped non-private manual network=$network"
                continue
            fi

        fi

        prefix="$(network_prefix "$network")"

        if (( prefix < NORDIC_DISCOVERY_MIN_PREFIX )); then
            log "[SKIP] Manual subnet too large: $network"
            ground_truth \
                "Skipped oversized manual network=$network"
            continue
        fi

        if network_is_excluded "$network"; then
            log "[SKIP] Excluded manual subnet: $network"
            ground_truth \
                "Excluded manual network=$network"
            continue
        fi

        # ----------------------------------------------------
        # Avoid duplicate networks already found by auto mode
        # ----------------------------------------------------

        if grep -q "^${network}|" "$NETWORK_TMP"; then
            log "[INFO] Manual subnet already present: $network"
            continue
        fi

        printf '%s|%s\n' \
            "$network" \
            "manual" \
            >> "$NETWORK_TMP"

        log "[NETWORK] $network via manual"

        ground_truth \
            "Discovery manual network=$network"

    done

fi

# ============================================================
# VERIFY NETWORKS
# ============================================================

NETWORK_COUNT="$(wc -l < "$NETWORK_TMP")"

if [[ "$NETWORK_COUNT" -eq 0 ]]; then

    log "[ERROR] No eligible CyberLab networks discovered."

    ground_truth "No eligible networks discovered"

    exit 1
fi


log "[INFO] Eligible networks: $NETWORK_COUNT"


# ============================================================
# WRITE NETWORK STATE
# ============================================================

python3 - \
    "$NETWORK_TMP" \
    "$NORDIC_NETWORK_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone

source = sys.argv[1]
destination = sys.argv[2]
incident_id = sys.argv[3]

networks = []

with open(source, encoding="utf-8") as handle:

    for line in handle:

        line = line.strip()

        if not line:
            continue

        network, interface = line.split("|", 1)

        networks.append(
            {
                "network": network,
                "interface": interface
            }
        )

state = {
    "incident_id": incident_id,
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": len(networks),
    "networks": networks
}

with open(
    destination,
    "w",
    encoding="utf-8"
) as handle:

    json.dump(
        state,
        handle,
        indent=2
    )

PY


# ============================================================
# HOST DISCOVERY
# ============================================================

echo

log "[INFO] Starting host discovery..."


TOTAL_HOSTS=0


while IFS='|' read -r network interface; do

    [[ -z "$network" ]] && continue


    echo
    log "[SCAN] $network via $interface"


    # --------------------------------------------------------
    # NMAP HOST DISCOVERY
    #
    # -sn = host discovery only
    # -n  = no DNS resolution
    #
    # No service/port scanning in Phase 01.
    # --------------------------------------------------------

    while read -r host; do

        [[ -z "$host" ]] && continue


        # ----------------------------------------------------
        # Never add IncidentVM itself
        # ----------------------------------------------------

        if [[ -n "${LOCAL_IPS[$host]+x}" ]]; then

            log "[SELF] $host"

            continue
        fi


        # ----------------------------------------------------
        # Duplicate host check
        # ----------------------------------------------------

        if grep -q "^${host}|" "$HOST_TMP"; then
            continue
        fi


        printf '%s|%s|%s\n' \
            "$host" \
            "$network" \
            "$interface" \
            >> "$HOST_TMP"


        TOTAL_HOSTS=$((TOTAL_HOSTS + 1))


        log "[HOST] $host"

        ground_truth \
            "Discovered host=$host network=$network interface=$interface"


        # ----------------------------------------------------
        # Safety limit
        # ----------------------------------------------------

        if (( TOTAL_HOSTS >= NORDIC_MAX_DISCOVERED_HOSTS )); then

            log "[WARN] Maximum discovered host limit reached."

            break 2
        fi


    done < <(

        nmap \
            -sn \
            -n \
            "$network" \
            -oG - \
            2>/dev/null \
        | awk '/Status: Up/ {print $2}'

    )


done < "$NETWORK_TMP"


# ============================================================
# WRITE HOST STATE
# ============================================================

python3 - \
    "$HOST_TMP" \
    "$NORDIC_DISCOVERED_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone

source = sys.argv[1]
destination = sys.argv[2]
incident_id = sys.argv[3]

hosts = []

with open(
    source,
    encoding="utf-8"
) as handle:

    for line in handle:

        line = line.strip()

        if not line:
            continue

        ip, network, interface = line.split(
            "|",
            2
        )

        hosts.append(
            {
                "ip": ip,
                "network": network,
                "interface": interface,

                "status": "discovered",

                "services": {},

                "ssh_candidate": False,
                "web_candidate": False,

                "compromised": False
            }
        )

state = {
    "incident_id": incident_id,

    "generated": datetime.now(
        timezone.utc
    ).isoformat(),

    "count": len(hosts),

    "hosts": hosts
}

with open(
    destination,
    "w",
    encoding="utf-8"
) as handle:

    json.dump(
        state,
        handle,
        indent=2
    )

PY


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 01 COMPLETE"
echo "============================================================"
echo

log "[INFO] Networks discovered : $NETWORK_COUNT"
log "[INFO] Hosts discovered    : $TOTAL_HOSTS"

echo

log "[INFO] Network state:"
log "       $NORDIC_NETWORK_STATE"

log "[INFO] Host state:"
log "       $NORDIC_DISCOVERED_STATE"

echo


ground_truth \
    "Dynamic discovery completed networks=$NETWORK_COUNT hosts=$TOTAL_HOSTS"


exit 0