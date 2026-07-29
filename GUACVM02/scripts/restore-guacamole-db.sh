#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/guacamole"
BACKUP_FILE="$APP_DIR/backups/guacamole-db.sql.gz"
cd "$APP_DIR"
[[ -s "$BACKUP_FILE" ]] || { echo "[FEJL] Backup findes ikke: $BACKUP_FILE" >&2; exit 1; }
set -a; source .env; set +a

echo "[+] Stopper Guacamole under restore."
docker compose stop guacamole

echo "[+] Gendanner $BACKUP_FILE"
gzip -dc "$BACKUP_FILE" | docker compose exec -T postgres \
  psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --set ON_ERROR_STOP=on

echo "[+] Starter Guacamole igen."
docker compose up -d guacamole nginx
docker compose ps
