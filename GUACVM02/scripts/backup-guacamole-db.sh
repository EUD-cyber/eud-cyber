#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/guacamole"
BACKUP_FILE="$APP_DIR/backups/guacamole-db.sql.gz"
cd "$APP_DIR"
set -a; source .env; set +a
mkdir -p backups
TMP="${BACKUP_FILE}.tmp"
docker compose exec -T postgres pg_dump \
  --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
  --clean --if-exists --no-owner --no-privileges | gzip -9 > "$TMP"
[[ -s "$TMP" ]] || { rm -f "$TMP"; echo "[FEJL] Backup er tom." >&2; exit 1; }
mv -f "$TMP" "$BACKUP_FILE"
chmod 600 "$BACKUP_FILE"
echo "[+] Backup oprettet: $BACKUP_FILE"
ls -lh "$BACKUP_FILE"
