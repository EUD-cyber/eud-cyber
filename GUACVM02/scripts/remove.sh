#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="/opt/guacamole"
[[ $EUID -eq 0 ]] || { echo "Kør som root."; exit 1; }
if [[ -d "$APP_DIR" ]]; then
  cd "$APP_DIR"
  docker compose down -v --remove-orphans || true
fi
rm -rf -- "$APP_DIR"
echo "[+] Cyberlab v2 Guacamole er fjernet."
