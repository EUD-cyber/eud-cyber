#!/usr/bin/env bash

set -Eeuo pipefail

APP_DIR="/opt/guacamole"
BACKUP_FILE="$APP_DIR/backups/guacamole-db.sql.gz"

POSTGRES_USER="guacamole_user"
POSTGRES_DB="guacamole_db"

log() {
    printf '[+] %s\n' "$*"
}

die() {
    printf '[FEJL] %s\n' "$*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] ||
    die "Kør scriptet som root eller med sudo."

[[ -s "$BACKUP_FILE" ]] ||
    die "Backupfilen findes ikke eller er tom: $BACKUP_FILE"

cd "$APP_DIR"

docker compose ps -q postgres >/dev/null 2>&1 ||
    die "PostgreSQL-containeren blev ikke fundet."

log "Stopper Guacamole og Nginx."

docker compose stop guacamole nginx || true

log "Afbryder aktive forbindelser til databasen."

docker compose exec -T postgres \
    psql \
    --username="$POSTGRES_USER" \
    --dbname=postgres \
    --set ON_ERROR_STOP=on \
    --command="
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '$POSTGRES_DB'
          AND pid <> pg_backend_pid();
    "

log "Sletter den eksisterende database."

docker compose exec -T postgres \
    dropdb \
    --username="$POSTGRES_USER" \
    --if-exists \
    "$POSTGRES_DB"

log "Opretter en tom database."

docker compose exec -T postgres \
    createdb \
    --username="$POSTGRES_USER" \
    --owner="$POSTGRES_USER" \
    "$POSTGRES_DB"

log "Importerer Guacamole-backupen."

gzip -dc "$BACKUP_FILE" |
    docker compose exec -T postgres \
        psql \
        --username="$POSTGRES_USER" \
        --dbname="$POSTGRES_DB" \
        --set ON_ERROR_STOP=on

log "Starter Guacamole og Nginx."

docker compose up -d guacamole nginx

log "Restore gennemført."

docker compose ps