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
gvm-setup || true

echo "[*] Opretter systemd override for gsad..."
mkdir -p /etc/systemd/system/gsad.service.d

cat > /etc/systemd/system/gsad.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/gsad --foreground --listen 0.0.0.0 --port 9392
EOF

echo "[*] Reload systemd..."
systemctl daemon-reload

echo "[*] Enabler services..."
systemctl enable ospd-openvas.service || true
systemctl enable gvmd.service || true
systemctl enable gsad.service || true

echo "[*] Restarter services i korrekt rækkefølge..."
systemctl restart ospd-openvas.service || true
systemctl restart gvmd.service || true
systemctl restart gsad.service || true

echo "[*] Verificerer aktiv ExecStart..."
systemctl cat gsad
systemctl status gsad --no-pager || true

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
