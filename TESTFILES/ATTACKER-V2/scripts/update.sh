#!/usr/bin/env bash

set -euo pipefail

#
# MrNobody Update Engine
#
# Shared update engine for:
#   - CLI
#   - Web GUI
#
# Source:
#   https://github.com/EUD-cyber/eud-cyber
#

INSTALL_DIR="${NORDIC_BASE_DIR:-/opt/nordic-attack}"

GITHUB_RAW_BASE="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/ATTACKER-V2"

REMOTE_MANIFEST_URL="${GITHUB_RAW_BASE}/update-manifest.txt"

TMP_DIR=""
CHANGED=0
NEW=0
UNCHANGED=0
FAILED=0

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

log() {
    printf '%s\n' "$*"
}

die() {
    log "ERROR: $*"
    exit 1
}

#
# Requirements
#
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

[[ -d "$INSTALL_DIR" ]] || die "MrNobody installation not found: $INSTALL_DIR"

TMP_DIR="$(mktemp -d)"

REMOTE_MANIFEST="${TMP_DIR}/update-manifest.txt"
DOWNLOAD_DIR="${TMP_DIR}/files"

mkdir -p "$DOWNLOAD_DIR"

log "========================================"
log " MrNobody Update"
log "========================================"
log
log "Installation: $INSTALL_DIR"
log
log "Checking GitHub..."

#
# Download current manifest from GitHub
#
curl \
    --fail \
    --silent \
    --show-error \
    --location \
    "$REMOTE_MANIFEST_URL" \
    -o "$REMOTE_MANIFEST" \
    || die "Could not download update manifest"

[[ -s "$REMOTE_MANIFEST" ]] || die "Downloaded manifest is empty"

log
log "Checking files..."
log

#
# Compare every file from the remote manifest.
#
while IFS='|' read -r EXPECTED_HASH RELATIVE_PATH; do

    #
    # Ignore comments and empty lines.
    #
    [[ -z "${EXPECTED_HASH:-}" ]] && continue
    [[ "$EXPECTED_HASH" == \#* ]] && continue
    [[ -z "${RELATIVE_PATH:-}" ]] && continue

    #
    # Basic path safety.
    #
    if [[ "$RELATIVE_PATH" == /* || "$RELATIVE_PATH" == *".."* ]]; then
        die "Unsafe path in manifest: $RELATIVE_PATH"
    fi

    LOCAL_FILE="${INSTALL_DIR}/${RELATIVE_PATH}"
    TEMP_FILE="${DOWNLOAD_DIR}/${RELATIVE_PATH}"

    if [[ ! -f "$LOCAL_FILE" ]]; then

        printf 'NEW      %s\n' "$RELATIVE_PATH"
        ((NEW+=1))

    else

        LOCAL_HASH="$(sha256sum "$LOCAL_FILE" | awk '{print $1}')"

        if [[ "$LOCAL_HASH" == "$EXPECTED_HASH" ]]; then

            printf 'MATCH    %s\n' "$RELATIVE_PATH"
            ((UNCHANGED+=1))
            continue

        else

            printf 'CHANGED  %s\n' "$RELATIVE_PATH"
            ((CHANGED+=1))

        fi
    fi

    #
    # Download NEW or CHANGED file into temporary storage.
    #
    mkdir -p "$(dirname "$TEMP_FILE")"

    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        "${GITHUB_RAW_BASE}/${RELATIVE_PATH}" \
        -o "$TEMP_FILE" \
        || {
            printf 'FAILED   %s\n' "$RELATIVE_PATH"
            ((FAILED+=1))
            continue
        }

    #
    # Verify downloaded file against manifest.
    #
    DOWNLOADED_HASH="$(sha256sum "$TEMP_FILE" | awk '{print $1}')"

    if [[ "$DOWNLOADED_HASH" != "$EXPECTED_HASH" ]]; then
        printf 'BAD HASH %s\n' "$RELATIVE_PATH"
        ((FAILED+=1))
        rm -f "$TEMP_FILE"
    fi

done < "$REMOTE_MANIFEST"

log
log "----------------------------------------"
log "Update check complete"
log
printf 'New:       %d\n' "$NEW"
printf 'Changed:   %d\n' "$CHANGED"
printf 'Unchanged: %d\n' "$UNCHANGED"
printf 'Failed:    %d\n' "$FAILED"
log "----------------------------------------"

if (( FAILED > 0 )); then
    die "Update aborted because one or more files failed validation"
fi

if (( NEW == 0 && CHANGED == 0 )); then
    log
    log "MrNobody is already up to date."
    exit 0
fi

log
log "Validating downloaded files..."

#
# Validate downloaded shell scripts.
#
while IFS= read -r -d '' FILE; do

    case "$FILE" in
        *.sh)
            printf 'BASH     %s\n' "${FILE#${DOWNLOAD_DIR}/}"

            bash -n "$FILE" || {
                die "Shell validation failed: ${FILE#${DOWNLOAD_DIR}/}"
            }
            ;;
    esac

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)

#
# Validate downloaded Python files.
#
while IFS= read -r -d '' FILE; do

    case "$FILE" in
        *.py)
            printf 'PYTHON   %s\n' "${FILE#${DOWNLOAD_DIR}/}"

            python3 -m py_compile "$FILE" || {
                die "Python validation failed: ${FILE#${DOWNLOAD_DIR}/}"
            }
            ;;
    esac

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)

log
log "Validation successful."
log
log "Installing updates..."

#
# Install downloaded NEW/CHANGED files.
#
while IFS= read -r -d '' TEMP_FILE; do

    RELATIVE_PATH="${TEMP_FILE#${DOWNLOAD_DIR}/}"
    TARGET_FILE="${INSTALL_DIR}/${RELATIVE_PATH}"

    mkdir -p "$(dirname "$TARGET_FILE")"

    install \
        -m 0644 \
        "$TEMP_FILE" \
        "$TARGET_FILE"

    #
    # Shell scripts and scenario scripts must be executable.
    #
    case "$RELATIVE_PATH" in
        scripts/*.sh|scenarios/*.sh)
            chmod 0755 "$TARGET_FILE"
            ;;
    esac

    printf 'UPDATED  %s\n' "$RELATIVE_PATH"

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)

log
log "========================================"
log " MrNobody update completed"
log "========================================"
log
printf 'New files:     %d\n' "$NEW"
printf 'Changed files: %d\n' "$CHANGED"
log
log "State, logs, runtime and reports were preserved."