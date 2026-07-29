#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/guacamole"
cd "$APP_DIR"
docker compose pull
docker compose up -d --remove-orphans
docker compose ps
