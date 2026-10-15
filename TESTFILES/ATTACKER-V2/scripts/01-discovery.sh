#!/usr/bin/env bash

set -u

# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 01 - Dynamic Network Discovery
#
# Purpose:
#
#   1. Detect directly connected private IPv4 networks
#   2. Exclude loopback and default-route-only networks
#   3. Discover active hosts
#   4. Create JSON inventory for later phases
#
# Output:
#
#   /opt/nordic-attack/state/networks.json
#   /opt/nordic-attack/state/discovered-hosts.json
#
# ============================================================


# ============================================================
# PATHS
# ============================================================

BASE_DIR="/opt/nordic-attack"

CONFIG_FILE="$BASE_DIR/config/defaults.conf"


# ============================================================
# LOAD CONFIGURATION
# ============================================================

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
# CAMPAIGN
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-01-discovery.log"

NETWORK_STATE="$NORDIC_NETWORK_STATE"

DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"


# ============================================================
# REQUIRED COMMANDS
# ============================================================

REQUIRED_COMMANDS=(
    ip
    python3
    nmap
)

for CMD in "${REQUIRED_COMMANDS[@]}"; do

    if ! command -v "$CMD" >/dev/null 2>&1; then

        echo "[ERROR] Required command not found: $CMD"
        exit 1

    fi

done


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

    printf '%s INCIDENT=%s PHASE=01 %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
}


# ============================================================
# BANNER
# ============================================================

echo
echo "============================================================"
echo " NORDIC MANUFACTURING"
echo " H3 INCIDENT CAMPAIGN V2"
echo " PHASE 01 - DYNAMIC DISCOVERY"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"


# ============================================================
# GET DEFAULT ROUTE INTERFACE
# ============================================================

DEFAULT_INTERFACE="$(
    ip -4 route show default 2>/dev/null |
    awk 'NR==1 {print $5}'
)"

if [[ -n "$DEFAULT_INTERFACE" ]]; then

    log "[*] Default route interface: $DEFAULT_INTERFACE"

else

    log "[*] No IPv4 default route interface detected."

fi


# ============================================================
# GET INTERFACE / NETWORK INFORMATION
# ============================================================
#
# Format generated internally:
#
# interface|address/prefix
#
# Example:
#
# eth0|192.168.1.254/24
# eth1|192.168.2.254/24
#
# ============================================================

mapfile -t INTERFACE_ADDRESSES < <(
    ip -o -4 addr show scope global |
    awk '{print $2 "|" $4}'
)


if [[ ${#INTERFACE_ADDRESSES[@]} -eq 0 ]]; then

    log "[ERROR] No global IPv4 interfaces detected."
    exit 1

fi


# ============================================================
# DETERMINE DIRECTLY CONNECTED PRIVATE NETWORKS
# ============================================================

NETWORK_RECORDS=()

for RECORD in "${INTERFACE_ADDRESSES[@]}"; do

    INTERFACE="${RECORD%%|*}"
    ADDRESS_CIDR="${RECORD#*|}"

    # --------------------------------------------------------
    # Ignore configured interfaces
    # --------------------------------------------------------

    IGNORE=0

    IFS=',' read -r -a IGNORED_INTERFACES \
        <<< "$NORDIC_DISCOVERY_IGNORE_INTERFACES"

    for IGNORED in "${IGNORED_INTERFACES[@]}"; do

        IGNORED="${IGNORED//[[:space:]]/}"

        if [[ "$INTERFACE" == "$IGNORED" ]]; then
            IGNORE=1
            break
        fi

    done

    if [[ "$IGNORE" -eq 1 ]]; then
        continue
    fi


    # --------------------------------------------------------
    # Convert interface CIDR to canonical network
    # --------------------------------------------------------

    NETWORK="$(
        python3 - "$ADDRESS_CIDR" <<'PY'
import ipaddress
import sys

try:
    interface = ipaddress.ip_interface(sys.argv[1])
    print(interface.network)
except ValueError:
    sys.exit(1)
PY
    )"

    if [[ -z "$NETWORK" ]]; then
        continue
    fi


    # --------------------------------------------------------
    # Verify private RFC1918 network
    # --------------------------------------------------------

    PRIVATE="$(
        python3 - "$NETWORK" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1])

    rfc1918 = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )

    print(
        "yes"
        if any(network.subnet_of(private) for private in rfc1918)
        else "no"
    )

except ValueError:
    print("no")
PY
    )"


    if [[ "$NORDIC_REQUIRE_PRIVATE_NETWORKS" == "1" ]] &&
       [[ "$PRIVATE" != "yes" ]]; then

        log "[SKIP] $INTERFACE $NETWORK is not an RFC1918 network."
        continue

    fi


    # --------------------------------------------------------
    # Prefix safety
    # --------------------------------------------------------

    PREFIX="${NETWORK#*/}"

    if (( PREFIX < NORDIC_DISCOVERY_MIN_PREFIX )); then

        log "[SKIP] $NETWORK is larger than allowed."
        continue

    fi


    # --------------------------------------------------------
    # Default route interface handling
    #
    # IMPORTANT:
    # We do NOT blindly exclude the interface containing the
    # default route.
    #
    # IncidentVM may legitimately have its CyberLab LAN and
    # default gateway on the same interface.
    #
    # We only use directly connected networks derived from
    # actual interface addresses.
    # --------------------------------------------------------

    NETWORK_RECORDS+=(
        "$INTERFACE|$ADDRESS_CIDR|$NETWORK|$PRIVATE"
    )

done


if [[ ${#NETWORK_RECORDS[@]} -eq 0 ]]; then

    log "[ERROR] No eligible private directly connected networks found."
    exit 1

fi


# ============================================================
# REMOVE DUPLICATE NETWORKS
# ============================================================

mapfile -t NETWORK_RECORDS < <(
    printf '%s\n' "${NETWORK_RECORDS[@]}" |
    awk -F'|' '!seen[$3]++'
)


# ============================================================
# DISPLAY NETWORKS
# ============================================================

echo
echo "Detected CyberLab networks:"
echo

for RECORD in "${NETWORK_RECORDS[@]}"; do

    INTERFACE="${RECORD%%|*}"

    REST="${RECORD#*|}"
    ADDRESS_CIDR="${REST%%|*}"

    REST="${REST#*|}"
    NETWORK="${REST%%|*}"

    printf "  %-12s %-20s %s\n" \
        "$INTERFACE" \
        "$ADDRESS_CIDR" \
        "$NETWORK"

    ground_truth \
        "NETWORK interface=$INTERFACE address=$ADDRESS_CIDR network=$NETWORK"

done

echo


# ============================================================
# WRITE networks.json
# ============================================================

TMP_NETWORKS="$NORDIC_STATE_DIR/.networks.tmp"

printf '%s\n' "${NETWORK_RECORDS[@]}" > "$TMP_NETWORKS"

python3 - \
    "$TMP_NETWORKS" \
    "$NETWORK_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone

source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]

networks = []

with open(source_file, "r", encoding="utf-8") as f:
    for line in f:

        line = line.strip()

        if not line:
            continue

        interface, address, network, private = line.split("|", 3)

        networks.append(
            {
                "interface": interface,
                "address": address,
                "network": network,
                "private": private == "yes",
            }
        )

data = {
    "incident_id": incident_id,
    "generated": datetime.now(timezone.utc).isoformat(),
    "networks": networks,
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY

rm -f "$TMP_NETWORKS"


# ============================================================
# HOST DISCOVERY
# ============================================================

DISCOVERED_RECORDS=()

TOTAL_DISCOVERED=0


for RECORD in "${NETWORK_RECORDS[@]}"; do

    INTERFACE="${RECORD%%|*}"

    REST="${RECORD#*|}"
    ADDRESS_CIDR="${REST%%|*}"

    REST="${REST#*|}"
    NETWORK="${REST%%|*}"

    INCIDENT_IP="${ADDRESS_CIDR%%/*}"

    echo
    log "[*] Discovering hosts on $NETWORK via $INTERFACE"
    echo


    # --------------------------------------------------------
    # nmap host discovery
    #
    # -sn = host discovery only
    #
    # We deliberately do NOT perform the attack/service
    # phases here.
    # --------------------------------------------------------

    mapfile -t FOUND_HOSTS < <(
        nmap \
            -sn \
            -n \
            "$NETWORK" \
            -oG - \
            2>/dev/null |
        awk '/Status: Up/ {print $2}'
    )


    for HOST in "${FOUND_HOSTS[@]}"; do

        # Do not attack/discover IncidentVM itself as target.

        if [[ "$HOST" == "$INCIDENT_IP" ]]; then
            continue
        fi


        # Avoid duplicates where multiple routes/interfaces
        # happen to expose the same host.

        DUPLICATE=0

        for EXISTING in "${DISCOVERED_RECORDS[@]}"; do

            EXISTING_IP="${EXISTING%%|*}"

            if [[ "$EXISTING_IP" == "$HOST" ]]; then
                DUPLICATE=1
                break
            fi

        done

        if [[ "$DUPLICATE" -eq 1 ]]; then
            continue
        fi


        TOTAL_DISCOVERED=$(( TOTAL_DISCOVERED + 1 ))


        if (( TOTAL_DISCOVERED > NORDIC_MAX_DISCOVERED_HOSTS )); then

            log "[WARNING] Maximum discovered host limit reached."
            break 2

        fi


        DISCOVERED_RECORDS+=(
            "$HOST|$NETWORK|$INTERFACE"
        )

        log "[+] Host discovered: $HOST"

        ground_truth \
            "HOST_DISCOVERED ip=$HOST network=$NETWORK interface=$INTERFACE"

    done

done


# ============================================================
# WRITE discovered-hosts.json
# ============================================================

TMP_HOSTS="$NORDIC_STATE_DIR/.hosts.tmp"

if [[ ${#DISCOVERED_RECORDS[@]} -gt 0 ]]; then

    printf '%s\n' \
        "${DISCOVERED_RECORDS[@]}" \
        > "$TMP_HOSTS"

else

    : > "$TMP_HOSTS"

fi


python3 - \
    "$TMP_HOSTS" \
    "$DISCOVERED_STATE" \
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

        line = line.strip()

        if not line:
            continue

        ip, network, interface = line.split("|", 2)

        hosts.append(
            {
                "ip": ip,
                "network": network,
                "interface": interface,

                "status": "discovered",

                "services": {},

                "ssh_candidate": False,
                "web_candidate": False,

                "compromised": False,
            }
        )


data = {
    "incident_id": incident_id,
    "generated": datetime.now(timezone.utc).isoformat(),
    "count": len(hosts),
    "hosts": hosts,
}


with open(output_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

PY


rm -f "$TMP_HOSTS"


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 01 COMPLETED"
echo "============================================================"
echo

echo "Networks discovered:"
echo "  ${#NETWORK_RECORDS[@]}"

echo

echo "Hosts discovered:"
echo "  ${#DISCOVERED_RECORDS[@]}"

echo

echo "Network state:"
echo "  $NETWORK_STATE"

echo

echo "Host inventory:"
echo "  $DISCOVERED_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE networks=${#NETWORK_RECORDS[@]} hosts=${#DISCOVERED_RECORDS[@]}"


exit 0