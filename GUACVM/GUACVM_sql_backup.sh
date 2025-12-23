#!/bin/bash
set -euo pipefail

# =========================
# CONFIG
# =========================
CONTAINER="postgres_guacamole_compose"
DB_NAME="guacamole_db"
DB_USER="guacamole_user"
DB_PASSWORD="Password1!"
BACKUP_DIR="/opt/guacamole-backups"

# =========================
# PREP
# =========================
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/guacamole_${TIMESTAMP}.sql.gz"

mkdir -p "$BACKUP_DIR"

# =========================
# BACKUP
# =========================
echo "[+] Starting Guacamole PostgreSQL backup..."

docker exec \
  -e PGPASSWORD="$DB_PASSWORD" \
  "$CONTAINER" \
  pg_dump -U "$DB_USER" "$DB_NAME" \
  | gzip > "$BACKUP_FILE"

echo "[+] Backup completed:"
echo "    $BACKUP_FILE"

# =========================
# VERIFY
# =========================
if [[ ! -s "$BACKUP_FILE" ]]; then
  echo "[-] Backup failed or empty!"
  exit 1
fi
