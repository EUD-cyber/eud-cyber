#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/guacamole"
ENV_FILE="$APP_DIR/.env"

log(){ printf '[+] %s\n' "$*"; }
die(){ printf '[FEJL] %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Kør scriptet som root eller med sudo."
cd "$APP_DIR"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 ca-certificates curl gzip
systemctl enable --now docker

mkdir -p postgres/init record drive backups
touch postgres/init/.gitkeep record/.gitkeep drive/.gitkeep backups/.gitkeep
chmod 777 record drive

if [[ ! -f "$ENV_FILE" ]]; then
  PASSWORD="$(openssl rand -base64 36 | tr -d '\n' | tr '/+' '_-')"
  cat > "$ENV_FILE" <<EOF
POSTGRES_DB=guacamole_db
POSTGRES_USER=guacamole_user
POSTGRES_PASSWORD=$PASSWORD
EOF
  chmod 600 "$ENV_FILE"
  log "Ny .env er oprettet."
fi

if [[ ! -s postgres/init/01-initdb.sql ]]; then
  log "Genererer Guacamole PostgreSQL-skema."
  docker run --rm guacamole/guacamole:1.6.0 \
    /opt/guacamole/bin/initdb.sh --postgresql > postgres/init/01-initdb.sql
fi

log "Starter Cyberlab v2."
docker compose up -d

log "Venter på PostgreSQL."
for _ in $(seq 1 40); do
  docker compose exec -T postgres pg_isready -U guacamole_user -d guacamole_db >/dev/null 2>&1 && break
  sleep 2
done

if [[ -s backups/guacamole-db.sql.gz ]]; then
  log "Databasebackup fundet. Gendanner automatisk."
  "$APP_DIR/scripts/restore-guacamole-db.sh"
fi

docker compose ps
log "Frontend: http://$(hostname -I | awk '{print $1}')/"
log "Guacamole: http://$(hostname -I | awk '{print $1}')/guacamole/"
