#!/usr/bin/env bash
set -Eeuo pipefail

LOG="/var/log/install-gvm.log"
exec > >(tee -a "$LOG") 2>&1

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Kør scriptet som root eller med sudo."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "[*] Opdaterer pakker..."
apt-get update -o Acquire::Retries=5
apt-get upgrade -y

echo "[*] Installerer GVM/OpenVAS..."
apt-get install -y gvm

echo "[*] Kører gvm-setup..."
gvm-setup

echo "[*] Finder gsad service-fil..."
GSAD_UNIT=""
for candidate in \
  /usr/lib/systemd/system/gsad.service \
  /lib/systemd/system/gsad.service
do
  if [[ -f "$candidate" ]]; then
    GSAD_UNIT="$candidate"
    break
  fi
done

if [[ -z "$GSAD_UNIT" ]]; then
  echo "[!] Kunne ikke finde gsad.service"
  exit 1
fi

echo "[*] Opdaterer gsad til at lytte på 0.0.0.0:9392 i $GSAD_UNIT ..."
cp "$GSAD_UNIT" "${GSAD_UNIT}.bak.$(date +%s)"

if grep -q -- '--listen=127.0.0.1' "$GSAD_UNIT"; then
  sed -i 's/--listen=127\.0\.0\.1/--listen=0.0.0.0/g' "$GSAD_UNIT"
elif grep -q -- '--listen 127.0.0.1' "$GSAD_UNIT"; then
  sed -i 's/--listen 127\.0\.0\.1/--listen 0.0.0.0/g' "$GSAD_UNIT"
fi

if grep -q -- '--port=443' "$GSAD_UNIT"; then
  sed -i 's/--port=443/--port=9392/g' "$GSAD_UNIT"
elif grep -q -- '--port 443' "$GSAD_UNIT"; then
  sed -i 's/--port 443/--port 9392/g' "$GSAD_UNIT"
fi

echo "[*] Reload systemd..."
systemctl daemon-reload

echo "[*] Enabler og starter services..."
systemctl enable --now ospd-openvas.service || true
systemctl enable --now gvmd.service || true
systemctl enable --now gsad.service || true

echo "[*] Starter hele GVM stakken..."
gvm-start || true

echo "[*] Verificerer installation..."
gvm-check-setup || true

echo "[*] Åbner firewall hvis UFW er aktiv..."
if command -v ufw >/dev/null 2>&1; then
  ufw allow 9392/tcp || true
fi

echo "[*] Lytter gsad på:"
ss -tulpen | grep 9392 || true

IP_ADDR="$(hostname -I | awk '{print $1}')"
echo
echo "[+] Færdig."
echo "[+] Web UI: https://${IP_ADDR}:9392"
echo "[+] Logfil: $LOG"
echo "[+] Hvis feed parsing stadig kører, kan første login/scan være forsinket."
