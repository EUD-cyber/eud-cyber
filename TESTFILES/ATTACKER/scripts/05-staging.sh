#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - Attack Simulation
# Phase 05 - Collection / Data Staging
#
# Purpose:
#   Simulate collection and staging of company data on an
#   already compromised Linux host.
#
# Flow:
#
#   IncidentVM
#       |
#       | SSH
#       v
#   Compromised Host
#       |
#       +-- Create synthetic company documents
#       +-- Discover documents
#       +-- Copy selected files
#       +-- Create staging archive
#       v
#   /tmp/.cache-update/nordic-data.tar.gz
#
# IMPORTANT:
#   Only synthetic CyberLab data is used.
# ============================================================

set -u

BASE_DIR="/opt/nordic-attack"
LOG_DIR="$BASE_DIR/logs"

mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOGFILE="$LOG_DIR/staging-$TIMESTAMP.log"
GROUNDTRUTH="$LOG_DIR/incident-ground-truth.log"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

log_event() {
    echo "$(date --iso-8601=seconds) | STAGING | $1" >> "$GROUNDTRUTH"
}

banner() {
    clear
    echo "============================================================"
    echo "    NORDIC MANUFACTURING - DATA STAGING"
    echo "============================================================"
    echo
}

validate_ipv4() {

    local IP="$1"

    if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<< "$IP"

    for octet in "$o1" "$o2" "$o3" "$o4"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done

    return 0
}


# ------------------------------------------------------------
# Dependency check
# ------------------------------------------------------------

if ! command -v sshpass >/dev/null 2>&1; then
    echo "[ERROR] sshpass is not installed."
    exit 1
fi


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

banner

echo "This phase simulates collection and staging of"
echo "synthetic Nordic Manufacturing company data."
echo

read -rp "Compromised host IP: " COMPROMISED_HOST

if ! validate_ipv4 "$COMPROMISED_HOST"; then
    echo
    echo "[ERROR] Invalid IPv4 address."
    exit 1
fi

echo

read -rp "SSH username: " SSH_USER
read -rsp "SSH password: " SSH_PASSWORD

echo
echo

echo "Compromised host: $COMPROMISED_HOST"
echo "SSH user:         $SSH_USER"
echo

log_event "Data collection started on $COMPROMISED_HOST"


# ------------------------------------------------------------
# Remote simulation
# ------------------------------------------------------------

REMOTE_COMMAND=$(cat <<'EOF'

set -e

LAB_DATA="$HOME/nordic-company-data"
STAGING="/tmp/.cache-update"

echo "===== COLLECTION / STAGING ====="
echo

echo "[TIME]"
date --iso-8601=seconds
echo

echo "[USER]"
whoami
echo

echo "[HOST]"
hostname
echo


# ------------------------------------------------------------
# Create synthetic company data
# ------------------------------------------------------------

echo "[+] Preparing synthetic company data"

mkdir -p "$LAB_DATA/finance"
mkdir -p "$LAB_DATA/hr"
mkdir -p "$LAB_DATA/it"
mkdir -p "$LAB_DATA/management"


cat > "$LAB_DATA/finance/customer-invoices.csv" <<'DATA'
invoice_id,customer,amount,status
INV-2026-1001,Contoso Production,48500,PAID
INV-2026-1002,Fabrikam Logistics,127500,OPEN
INV-2026-1003,Northwind Industrial,76000,OPEN
INV-2026-1004,Adventure Components,33200,PAID
DATA


cat > "$LAB_DATA/hr/employees.csv" <<'DATA'
employee_id,name,department,email
NM001,Anna Jensen,Finance,anna.jensen@nordic.example
NM002,Lars Nielsen,Production,lars.nielsen@nordic.example
NM003,Maria Hansen,IT,maria.hansen@nordic.example
NM004,Peter Sørensen,Management,peter.sorensen@nordic.example
DATA


cat > "$LAB_DATA/it/server-inventory.txt" <<'DATA'
NORDIC MANUFACTURING - INTERNAL SERVER INVENTORY

DC01       Windows Server       Active Directory
FILE01     Windows Server       Corporate File Server
WEB01      Ubuntu               Webshop
BACKUP01   Linux                Backup Server
SIEM01     Linux                Security Monitoring

CLASSIFICATION: INTERNAL
DATA


cat > "$LAB_DATA/management/strategy-2027.txt" <<'DATA'
NORDIC MANUFACTURING A/S
CONFIDENTIAL - MANAGEMENT

2027 Strategic Planning Draft

- Expansion of production capacity
- New supplier agreements
- ERP modernization project
- OT network modernization
- Cybersecurity improvement programme

CLASSIFICATION: CONFIDENTIAL
DATA


# ------------------------------------------------------------
# Discovery
# ------------------------------------------------------------

echo
echo "[+] Searching for interesting files"

find "$LAB_DATA" \
    -type f \
    \( -name "*.csv" -o -name "*.txt" -o -name "*.conf" \) \
    -print

echo

du -ah "$LAB_DATA"


# ------------------------------------------------------------
# Staging
# ------------------------------------------------------------

echo
echo "[+] Creating staging directory"

rm -rf "$STAGING"
mkdir -p "$STAGING/collection"


echo
echo "[+] Copying selected files"

cp "$LAB_DATA/finance/customer-invoices.csv" \
   "$STAGING/collection/"

cp "$LAB_DATA/hr/employees.csv" \
   "$STAGING/collection/"

cp "$LAB_DATA/it/server-inventory.txt" \
   "$STAGING/collection/"

cp "$LAB_DATA/management/strategy-2027.txt" \
   "$STAGING/collection/"


# ------------------------------------------------------------
# Create manifest
# ------------------------------------------------------------

echo
echo "[+] Creating file manifest"

find "$STAGING/collection" \
    -type f \
    -exec sha256sum {} \; \
    > "$STAGING/manifest.txt"


# ------------------------------------------------------------
# Compress staged data
# ------------------------------------------------------------

echo
echo "[+] Compressing collected data"

tar \
    -czf "$STAGING/nordic-data.tar.gz" \
    -C "$STAGING" \
    collection manifest.txt


# ------------------------------------------------------------
# Evidence
# ------------------------------------------------------------

echo
echo "===== STAGED FILES ====="

ls -lah "$STAGING"

echo

echo "===== ARCHIVE ====="

ls -lh "$STAGING/nordic-data.tar.gz"

echo

echo "===== SHA256 ====="

sha256sum "$STAGING/nordic-data.tar.gz"

echo

echo "===== STAGING COMPLETE ====="

EOF
)


# ------------------------------------------------------------
# Execute
# ------------------------------------------------------------

echo "[1/3] Connecting to compromised host..."

log_event "SSH session opened to $COMPROMISED_HOST for collection"


sshpass -p "$SSH_PASSWORD" \
    ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    "$SSH_USER@$COMPROMISED_HOST" \
    "$REMOTE_COMMAND" >> "$LOGFILE" 2>&1

SSH_RESULT=$?


# ------------------------------------------------------------
# Result
# ------------------------------------------------------------

if [[ "$SSH_RESULT" -ne 0 ]]; then

    echo
    echo "[ERROR] Data staging failed."

    log_event "Data staging FAILED on $COMPROMISED_HOST"

    exit 1

fi


echo
echo "[2/3] Synthetic company data collected."

log_event "Synthetic company files collected on $COMPROMISED_HOST"

sleep 2


echo
echo "[3/3] Data archive created."

log_event "Staging archive created at /tmp/.cache-update/nordic-data.tar.gz on $COMPROMISED_HOST"

sleep 2


# ------------------------------------------------------------
# Finish
# ------------------------------------------------------------

log_event "Data staging completed on $COMPROMISED_HOST"


echo
echo "============================================================"
echo " Data staging completed"
echo "============================================================"
echo
echo "Compromised host:"
echo "  $COMPROMISED_HOST"
echo
echo "Remote staging directory:"
echo "  /tmp/.cache-update/"
echo
echo "Staged archive:"
echo "  /tmp/.cache-update/nordic-data.tar.gz"
echo
echo "Attack log:"
echo "  $LOGFILE"
echo
echo "Ground truth:"
echo "  $GROUNDTRUTH"
echo