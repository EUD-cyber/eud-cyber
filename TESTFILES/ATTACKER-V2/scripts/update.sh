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
DOWNLOAD_DIR=""
BACKUP_DIR=""

CHANGED=0
NEW=0
UNCHANGED=0
FAILED=0

NGINX_CHANGED=0
SYSTEMD_CHANGED=0
WEB_CHANGED=0

UPDATE_STARTED=0


# ============================================================
# CLEANUP
# ============================================================

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT


# ============================================================
# LOGGING
# ============================================================

log() {
    printf '%s\n' "$*"
}

die() {
    log
    log "ERROR: $*"
    exit 1
}


# ============================================================
# REQUIREMENTS
# ============================================================

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
command -v install >/dev/null 2>&1 || die "install is required"
command -v find >/dev/null 2>&1 || die "find is required"

[[ -d "$INSTALL_DIR" ]] || \
    die "MrNobody installation not found: $INSTALL_DIR"


# ============================================================
# TEMPORARY WORKSPACE
# ============================================================

TMP_DIR="$(mktemp -d)"

REMOTE_MANIFEST="${TMP_DIR}/update-manifest.txt"
DOWNLOAD_DIR="${TMP_DIR}/files"
BACKUP_DIR="${TMP_DIR}/backup"

mkdir -p \
    "$DOWNLOAD_DIR" \
    "$BACKUP_DIR"


# ============================================================
# HEADER
# ============================================================

log "========================================"
log " MrNobody Update"
log "========================================"
log
log "Installation: $INSTALL_DIR"
log
log "Checking GitHub..."


# ============================================================
# DOWNLOAD MANIFEST
# ============================================================

curl \
    --fail \
    --silent \
    --show-error \
    --location \
    "$REMOTE_MANIFEST_URL" \
    -o "$REMOTE_MANIFEST" \
    || die "Could not download update manifest"

[[ -s "$REMOTE_MANIFEST" ]] || \
    die "Downloaded manifest is empty"


# ============================================================
# COMPARE FILES
# ============================================================

log
log "Checking files..."
log

while IFS='|' read -r EXPECTED_HASH RELATIVE_PATH; do

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

    mkdir -p "$(dirname "$TEMP_FILE")"

    #
    # Download NEW or CHANGED file.
    #
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
    # Verify downloaded file.
    #
    DOWNLOADED_HASH="$(sha256sum "$TEMP_FILE" | awk '{print $1}')"

    if [[ "$DOWNLOADED_HASH" != "$EXPECTED_HASH" ]]; then

        printf 'BAD HASH %s\n' "$RELATIVE_PATH"

        ((FAILED+=1))

        rm -f "$TEMP_FILE"
    fi

done < "$REMOTE_MANIFEST"


# ============================================================
# UPDATE SUMMARY
# ============================================================

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


# ============================================================
# VALIDATE DOWNLOADS
# ============================================================

log
log "Validating downloaded files..."
log

#
# Shell
#
while IFS= read -r -d '' FILE; do

    case "$FILE" in

        *.sh)

            printf 'BASH     %s\n' \
                "${FILE#${DOWNLOAD_DIR}/}"

            bash -n "$FILE" || \
                die "Shell validation failed: ${FILE#${DOWNLOAD_DIR}/}"

            ;;

    esac

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)

#
# Python
#
while IFS= read -r -d '' FILE; do

    case "$FILE" in

        *.py)

            printf 'PYTHON   %s\n' \
                "${FILE#${DOWNLOAD_DIR}/}"

            python3 -m py_compile "$FILE" || \
                die "Python validation failed: ${FILE#${DOWNLOAD_DIR}/}"

            ;;

    esac

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)


# ============================================================
# PRE-VALIDATE NGINX
# ============================================================

if [[ -f "${DOWNLOAD_DIR}/nginx/nordic-incident.conf" ]]; then

    log
    log "Nginx configuration update detected."

    command -v nginx >/dev/null 2>&1 || \
        die "nginx is required for this update"

    NGINX_CHANGED=1
fi


# ============================================================
# DETECT SYSTEMD UPDATE
# ============================================================

if [[ -f "${DOWNLOAD_DIR}/systemd/nordic-incident-web.service" ]]; then

    log
    log "Systemd service update detected."

    SYSTEMD_CHANGED=1
fi


# ============================================================
# DETECT WEB UPDATE
# ============================================================

if find "$DOWNLOAD_DIR/web" \
    -type f \
    -print \
    -quit \
    2>/dev/null \
    | grep -q .
then
    WEB_CHANGED=1
fi


# ============================================================
# CREATE BACKUP
# ============================================================

log
log "Creating rollback backup..."

while IFS= read -r -d '' TEMP_FILE; do

    RELATIVE_PATH="${TEMP_FILE#${DOWNLOAD_DIR}/}"
    LOCAL_FILE="${INSTALL_DIR}/${RELATIVE_PATH}"

    if [[ -f "$LOCAL_FILE" ]]; then

        BACKUP_FILE="${BACKUP_DIR}/install/${RELATIVE_PATH}"

        mkdir -p "$(dirname "$BACKUP_FILE")"

        cp -a \
            "$LOCAL_FILE" \
            "$BACKUP_FILE"

        printf 'BACKUP   %s\n' "$RELATIVE_PATH"
    fi

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)

#
# Backup active nginx configuration.
#
if (( NGINX_CHANGED == 1 )); then

    if [[ -f /etc/nginx/sites-available/nordic-incident.conf ]]; then

        mkdir -p "${BACKUP_DIR}/system/nginx"

        cp -a \
            /etc/nginx/sites-available/nordic-incident.conf \
            "${BACKUP_DIR}/system/nginx/nordic-incident.conf"
    fi
fi

#
# Backup active systemd unit.
#
if (( SYSTEMD_CHANGED == 1 )); then

    if [[ -f /etc/systemd/system/nordic-incident-web.service ]]; then

        mkdir -p "${BACKUP_DIR}/system/systemd"

        cp -a \
            /etc/systemd/system/nordic-incident-web.service \
            "${BACKUP_DIR}/system/systemd/nordic-incident-web.service"
    fi
fi


# ============================================================
# ROLLBACK FUNCTION
# ============================================================

rollback() {

    local rc="${1:-1}"

    set +e

    log
    log "========================================"
    log " UPDATE FAILED - STARTING ROLLBACK"
    log "========================================"
    log

    #
    # Restore MrNobody files.
    #
    if [[ -d "${BACKUP_DIR}/install" ]]; then

        while IFS= read -r -d '' BACKUP_FILE; do

            RELATIVE_PATH="${BACKUP_FILE#${BACKUP_DIR}/install/}"
            TARGET_FILE="${INSTALL_DIR}/${RELATIVE_PATH}"

            mkdir -p "$(dirname "$TARGET_FILE")"

            cp -a \
                "$BACKUP_FILE" \
                "$TARGET_FILE"

            printf 'RESTORED %s\n' "$RELATIVE_PATH"

        done < <(
            find "${BACKUP_DIR}/install" \
                -type f \
                -print0
        )
    fi

    #
    # Remove NEW files that did not exist before the update.
    #
    while IFS= read -r -d '' TEMP_FILE; do

        RELATIVE_PATH="${TEMP_FILE#${DOWNLOAD_DIR}/}"

        if [[ ! -f "${BACKUP_DIR}/install/${RELATIVE_PATH}" ]]; then

            rm -f \
                "${INSTALL_DIR}/${RELATIVE_PATH}"

            printf 'REMOVED  %s\n' "$RELATIVE_PATH"
        fi

    done < <(
        find "$DOWNLOAD_DIR" \
            -type f \
            -print0
    )

    #
    # Restore nginx.
    #
    if [[ -f "${BACKUP_DIR}/system/nginx/nordic-incident.conf" ]]; then

        cp -a \
            "${BACKUP_DIR}/system/nginx/nordic-incident.conf" \
            /etc/nginx/sites-available/nordic-incident.conf
    fi

    #
    # Restore systemd service.
    #
    if [[ -f "${BACKUP_DIR}/system/systemd/nordic-incident-web.service" ]]; then

        cp -a \
            "${BACKUP_DIR}/system/systemd/nordic-incident-web.service" \
            /etc/systemd/system/nordic-incident-web.service
    fi

    systemctl daemon-reload \
        >/dev/null 2>&1 || true

    nginx -t \
        >/dev/null 2>&1 || true

    systemctl restart \
        nordic-incident-web.service \
        >/dev/null 2>&1 || true

    systemctl reload nginx \
        >/dev/null 2>&1 || true

    log
    log "Rollback completed."
    log "Previous MrNobody installation restored."
    log

    exit "$rc"
}


# ============================================================
# INSTALL UPDATE
# ============================================================

UPDATE_STARTED=1

log
log "Installing updates..."

while IFS= read -r -d '' TEMP_FILE; do

    RELATIVE_PATH="${TEMP_FILE#${DOWNLOAD_DIR}/}"
    TARGET_FILE="${INSTALL_DIR}/${RELATIVE_PATH}"

    mkdir -p "$(dirname "$TARGET_FILE")"

    install \
        -m 0644 \
        "$TEMP_FILE" \
        "$TARGET_FILE" \
        || rollback $?

    #
    # Executable files.
    #
    case "$RELATIVE_PATH" in

        scripts/*.sh|scenarios/*.sh)

            chmod 0755 "$TARGET_FILE" \
                || rollback $?

            ;;

    esac

    printf 'UPDATED  %s\n' "$RELATIVE_PATH"

done < <(
    find "$DOWNLOAD_DIR" \
        -type f \
        -print0
)


# ============================================================
# ACTIVATE SYSTEMD UPDATE
# ============================================================

if (( SYSTEMD_CHANGED == 1 )); then

    log
    log "Installing systemd service..."

    install \
        -m 0644 \
        "${INSTALL_DIR}/systemd/nordic-incident-web.service" \
        /etc/systemd/system/nordic-incident-web.service \
        || rollback $?

    systemctl daemon-reload \
        || rollback $?
fi


# ============================================================
# ACTIVATE NGINX UPDATE
# ============================================================

if (( NGINX_CHANGED == 1 )); then

    log
    log "Installing nginx configuration..."

    install \
        -m 0644 \
        "${INSTALL_DIR}/nginx/nordic-incident.conf" \
        /etc/nginx/sites-available/nordic-incident.conf \
        || rollback $?

    nginx -t \
        || rollback $?
fi


# ============================================================
# RESTART SERVICES
# ============================================================

if (( SYSTEMD_CHANGED == 1 || WEB_CHANGED == 1 )); then

    log
    log "Restarting MrNobody web service..."

    systemctl restart \
        nordic-incident-web.service \
        || rollback $?
fi

if (( NGINX_CHANGED == 1 )); then

    log
    log "Reloading nginx..."

    systemctl reload nginx \
        || rollback $?
fi


# ============================================================
# HEALTH CHECK
# ============================================================

if (( SYSTEMD_CHANGED == 1 || WEB_CHANGED == 1 || NGINX_CHANGED == 1 )); then

    log
    log "Checking MrNobody health..."

    sleep 2

    curl \
        --insecure \
        --fail \
        --silent \
        --show-error \
        --max-time 10 \
        https://127.0.0.1/api/health \
        >/dev/null \
        || rollback $?

    log "Health check successful."
fi


# ============================================================
# COMPLETE
# ============================================================

log
log "========================================"
log " MrNobody update completed"
log "========================================"
log

printf 'New files:     %d\n' "$NEW"
printf 'Changed files: %d\n' "$CHANGED"

log
log "State, logs, runtime and reports were preserved."