#!/usr/bin/env bash

set -euo pipefail

#
# MrNobody Dynamic Attack Runner
#
# Supports:
#
#   run-phase.sh list
#   run-phase.sh all
#   run-phase.sh <attack-id>
#   run-phase.sh <attack-alias>
#
# Standalone overrides:
#
#   --target <ip/host>
#   --port <port>
#   --protocol <protocol>
#   --user <username>
#   --password <password>
#
# Attack scripts are discovered dynamically.
#
# Example metadata inside an attack script:
#
#   # ATTACK_ID="04"
#   # ATTACK_NAME="Internal Discovery"
#   # ATTACK_ALIAS="lateral"
#   # ATTACK_STANDALONE="true"
#   # ATTACK_PARAMETERS="target,port,protocol,username,password"
#   # ATTACK_CAMPAIGN_STATE="compromised-hosts"
#   # MITRE_TACTIC="Discovery"
#   # MITRE_TECHNIQUES="T1082,T1016,T1018"
#

BASE_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"

SCRIPT_DIR="${BASE_DIR}/scripts"
SCENARIO_DIR="${BASE_DIR}/scenarios"

FULL_CAMPAIGN="${SCENARIO_DIR}/full-incident-h3.sh"


# ============================================================
# ARGUMENTS
# ============================================================

COMMAND="${1:-list}"

SOURCE=""
TARGET=""
PORT=""
PROTOCOL=""
USERNAME=""
PASSWORD=""
FILE=""
SUBNET=""
AUTO_DISCOVERY=""

DRY_RUN=0


# ============================================================
# LOGGING
# ============================================================

log() {
    printf '%s\n' "$*"
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}


# ============================================================
# REQUIREMENTS
# ============================================================

[[ -d "$SCRIPT_DIR" ]] || \
    die "Scripts directory not found: $SCRIPT_DIR"


# ============================================================
# METADATA
# ============================================================

#
# Read one metadata value from the beginning of an attack script.
#
# Example:
#
#   # ATTACK_NAME="Internal Discovery"
#
metadata() {

    local file="$1"
    local key="$2"

    local line

    line="$(
        grep -m1 -E "^#[[:space:]]*${key}=" "$file" 2>/dev/null \
            || true
    )"

    [[ -n "$line" ]] || return 1

    line="${line#*=}"

    #
    # Remove optional surrounding quotes.
    #
    line="${line%\"}"
    line="${line#\"}"

    line="${line%\'}"
    line="${line#\'}"

    printf '%s\n' "$line"
}


# ============================================================
# ATTACK DISCOVERY
# ============================================================

#
# An attack script must currently match:
#
#   scripts/NN-*.sh
#
# Future attacks therefore automatically become available
# without modifying this runner.
#
discover_attacks() {

    find "$SCRIPT_DIR" \
        -maxdepth 1 \
        -type f \
        -regextype posix-extended \
        -regex '.*/[0-9]+-[^/]+\.sh' \
        -print \
        | sort -V
}


# ============================================================
# FALLBACK METADATA
# ============================================================

#
# Existing P01-P08 do not yet contain full ATTACK_* metadata.
# Until they are converted, derive ID and name from filename.
#

fallback_id() {

    local file="$1"
    local base

    base="$(basename "$file")"

    printf '%s\n' "${base%%-*}"
}


fallback_alias() {

    local file="$1"
    local base

    base="$(basename "$file" .sh)"
    base="${base#*-}"

    printf '%s\n' "$base"
}


fallback_name() {

    local alias

    alias="$(fallback_alias "$1")"

    printf '%s\n' \
        "$alias" \
        | tr '-' ' ' \
        | sed -E 's/(^| )([a-z])/\1\u\2/g'
}


attack_id() {

    local file="$1"

    metadata "$file" ATTACK_ID 2>/dev/null \
        || fallback_id "$file"
}


attack_name() {

    local file="$1"

    metadata "$file" ATTACK_NAME 2>/dev/null \
        || fallback_name "$file"
}


attack_alias() {

    local file="$1"

    metadata "$file" ATTACK_ALIAS 2>/dev/null \
        || fallback_alias "$file"
}


# ============================================================
# LIST ATTACKS
# ============================================================

list_attacks() {

    local count=0

    echo "========================================"
    echo " MrNobody Attacks"
    echo "========================================"
    echo

    printf '%-6s %-22s %-15s %-12s %s\n' \
        "ID" \
        "NAME" \
        "ALIAS" \
        "STANDALONE" \
        "MITRE"

    printf '%-6s %-22s %-15s %-12s %s\n' \
        "------" \
        "----------------------" \
        "---------------" \
        "------------" \
        "--------------------"

    while IFS= read -r file; do

        [[ -n "$file" ]] || continue

        local id
        local name
        local alias
        local standalone
        local mitre

        id="$(attack_id "$file")"
        name="$(attack_name "$file")"
        alias="$(attack_alias "$file")"

        standalone="$(
            metadata "$file" ATTACK_STANDALONE 2>/dev/null \
                || printf 'not-defined'
        )"

        mitre="$(
            metadata "$file" MITRE_TECHNIQUES 2>/dev/null \
                || printf '-'
        )"

        printf '%-6s %-22s %-15s %-12s %s\n' \
            "$id" \
            "$name" \
            "$alias" \
            "$standalone" \
            "$mitre"

        ((count+=1))

    done < <(discover_attacks)

    echo
    echo "Attacks discovered: $count"
}


# ============================================================
# FIND ATTACK
# ============================================================

find_attack() {

    local selector="$1"
    local file

    while IFS= read -r file; do

        [[ -n "$file" ]] || continue

        local id
        local alias

        id="$(attack_id "$file")"
        alias="$(attack_alias "$file")"

        #
        # Accept:
        #
        #   4
        #   04
        #   lateral
        #
        if [[ "$selector" == "$id" || "$selector" == "$alias" ]]; then
            printf '%s\n' "$file"
            return 0
        fi

        #
        # Numeric comparison lets "4" match "04".
        #
        if [[ "$selector" =~ ^[0-9]+$ && "$id" =~ ^[0-9]+$ ]]; then

            if (( 10#$selector == 10#$id )); then
                printf '%s\n' "$file"
                return 0
            fi
        fi

    done < <(discover_attacks)

    return 1
}


# ============================================================
# PARAMETER VALIDATION
# ============================================================

validate_port() {

    [[ -z "$PORT" ]] && return 0

    [[ "$PORT" =~ ^[0-9]+$ ]] || \
        die "Invalid port: $PORT"

    (( PORT >= 1 && PORT <= 65535 )) || \
        die "Port must be between 1 and 65535"
}


# ============================================================
# RUN FULL CAMPAIGN
# ============================================================

run_all() {

    [[ -x "$FULL_CAMPAIGN" ]] || \
        die "Full campaign script not found or not executable: $FULL_CAMPAIGN"

    echo "========================================"
    echo " MrNobody Full Campaign"
    echo "========================================"
    echo

    if (( DRY_RUN == 1 )); then
        echo "DRY RUN:"
        echo "$FULL_CAMPAIGN"
        return 0
    fi

    exec "$FULL_CAMPAIGN"
}


# ============================================================
# RUN SINGLE ATTACK
# ============================================================

run_attack() {

    local selector="$1"
    local file

    file="$(find_attack "$selector")" || \
        die "Attack not found: $selector"

    local id
    local name
    local alias
    local standalone
    local parameters
    local tactic
    local techniques

    id="$(attack_id "$file")"
    name="$(attack_name "$file")"
    alias="$(attack_alias "$file")"

    standalone="$(
        metadata "$file" ATTACK_STANDALONE 2>/dev/null \
            || printf 'not-defined'
    )"

    parameters="$(
        metadata "$file" ATTACK_PARAMETERS 2>/dev/null \
            || printf ''
    )"

    tactic="$(
        metadata "$file" MITRE_TACTIC 2>/dev/null \
            || printf '-'
    )"

    techniques="$(
        metadata "$file" MITRE_TECHNIQUES 2>/dev/null \
            || printf '-'
    )"

    echo "========================================"
    echo " MrNobody Attack"
    echo "========================================"
    echo
    echo "ID:          $id"
    echo "Name:        $name"
    echo "Alias:       $alias"
    echo "Script:      $file"
    echo "MITRE:       $tactic / $techniques"
    echo

    #
    # Determine mode.
    #
    if  [[ -n "$SOURCE" ]] ||
        [[ -n "$TARGET" ]] ||
        [[ -n "$SUBNET" ]] ||
        [[ -n "$AUTO_DISCOVERY" ]]; then

        RUN_MODE="standalone"

    else

        RUN_MODE="campaign"

    fi

    echo "Mode:        $MODE"

    if [[ "$MODE" == "standalone" ]]; then

        echo "Target:      ${TARGET:-not-set}"
        echo "Port:        ${PORT:-automatic}"
        echo "Protocol:    ${PROTOCOL:-automatic}"
        echo "Username:    ${USERNAME:-not-set}"

        #
        # Never print password.
        #
        if [[ -n "$PASSWORD" ]]; then
            echo "Password:    supplied"
        else
            echo "Password:    not-set"
        fi

        if [[ -n "$FILE" ]]; then
            echo "File:        $FILE"
        fi

        if [[ -n "$parameters" ]]; then
            echo "Parameters:  $parameters"
        fi
    fi

    echo

    validate_port

    #
    # Export generic runner variables.
    #
    # Individual attack scripts will gradually be converted
    # to consume these variables.
    #
    export MRNOBODY_RUN_MODE="$MODE"

    export MRNOBODY_SOURCE="$SOURCE"
    export MRNOBODY_TARGET="$TARGET"
    export MRNOBODY_PORT="$PORT"
    export MRNOBODY_PROTOCOL="$PROTOCOL"
    export MRNOBODY_USERNAME="$USERNAME"
    export MRNOBODY_PASSWORD="$PASSWORD"
    export MRNOBODY_FILE="$FILE"

    export MRNOBODY_SUBNET="$SUBNET"

    if [[ -n "$AUTO_DISCOVERY" ]]; then
        export MRNOBODY_AUTO="$AUTO_DISCOVERY"
    fi

    export MRNOBODY_ATTACK_ID="$id"
    export MRNOBODY_ATTACK_NAME="$name"
    export MRNOBODY_ATTACK_ALIAS="$alias"

    if (( DRY_RUN == 1 )); then

        echo "DRY RUN"
        echo
        echo "Would execute:"
        echo "$file"

        return 0
    fi

    #
    # Important:
    #
    # Existing attack scripts currently still primarily use
    # campaign state. Standalone behavior is introduced into
    # each phase separately.
    #
    exec "$file"
}


# ============================================================
# HELP
# ============================================================

usage() {

    cat <<'EOF'
MrNobody Dynamic Attack Runner

Usage:

  run-phase.sh list
  run-phase.sh all
  run-phase.sh <attack>
  run-phase.sh <attack> [options]

Attack may be:

  ID
  alias

Examples:

  run-phase.sh list

  run-phase.sh all

  run-phase.sh 04

  run-phase.sh lateral

  run-phase.sh 04 \
    --source 192.168.1.20 \
    --target 192.168.1.30 \
    --port 22 \
    --protocol ssh \
    --user ubuntu \
    --password password

Options:

  --source <host>
  --target <host>
  --port <port>
  --protocol <protocol>
  --user <username>
  --password <password>
  --file <path>
  --dry-run
  --help
  --auto
  --subnet <cidr[,cidr...]>

Without --source or --target:
  Campaign mode is used.

With --source or --target:
  Standalone mode is used.

EOF
}


# ============================================================
# COMMAND PARSING
# ============================================================

case "$COMMAND" in

    list|phases|attacks)

        shift || true

        list_attacks
        exit 0
        ;;

    all)

        shift || true

        while (( $# > 0 )); do

            case "$1" in

                --dry-run)
                    DRY_RUN=1
                    shift
                    ;;

                --help|-h)
                    usage
                    exit 0
                    ;;

                *)
                    die "Unknown option for full campaign: $1"
                    ;;

            esac

        done

        run_all
        ;;

    help|--help|-h)

        usage
        exit 0
        ;;

    *)

        ATTACK_SELECTOR="$COMMAND"

        shift || true

        while (( $# > 0 )); do

            case "$1" in

                --source)

                    [[ $# -ge 2 ]] || \
                        die "--source requires a value"

                    SOURCE="$2"
                    shift 2
                    ;;

                --target)

                    [[ $# -ge 2 ]] || \
                        die "--target requires a value"

                    TARGET="$2"
                    shift 2
                    ;;

                --subnet)
                    [[ $# -ge 2 ]] || \
                        die "--subnet requires a value"

                    SUBNET="$2"
                    shift 2
                    ;;

                --auto)
                    AUTO_DISCOVERY="1"
                    shift
                    ;;

                --port)

                    [[ $# -ge 2 ]] || \
                        die "--port requires a value"

                    PORT="$2"
                    shift 2
                    ;;

                --protocol)

                    [[ $# -ge 2 ]] || \
                        die "--protocol requires a value"

                    PROTOCOL="$2"
                    shift 2
                    ;;

                --user|--username)

                    [[ $# -ge 2 ]] || \
                        die "--user requires a value"

                    USERNAME="$2"
                    shift 2
                    ;;

                --password)

                    [[ $# -ge 2 ]] || \
                        die "--password requires a value"

                    PASSWORD="$2"
                    shift 2
                    ;;

                --file)

                    [[ $# -ge 2 ]] || \
                        die "--file requires a value"

                    FILE="$2"
                    shift 2
                    ;;

                --dry-run)

                    DRY_RUN=1
                    shift
                    ;;

                --help|-h)

                    usage
                    exit 0
                    ;;

                *)

                    die "Unknown option: $1"
                    ;;

            esac

        done

        run_attack "$ATTACK_SELECTOR"
        ;;

esac