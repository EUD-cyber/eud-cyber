#!/usr/bin/env bash
set -Eeuo pipefail

LOG="/var/log/install-gvm.log"
exec > >(tee -a "$LOG") 2>&1

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Kør som root eller med sudo"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "[*] Opdaterer system..."
apt update
apt full-upgrade -y

echo "[*] Installerer GVM..."
apt install -y gvm

echo "[*] Kører gvm-setup (kan tage lang tid)..."
gvm-setup

echo "setting admin password"
sudo runuser -u _gvm -- gvmd --user=admin --new-password='Password1!'

echo "[*] Opretter systemd override for ekstern adgang..."
mkdir -p /etc/systemd/system/gsad.service.d

cat > /etc/systemd/system/gsad.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/gsad --foreground --listen=0.0.0.0 --port=9392
EOF

echo "[*] Reload systemd..."
systemctl daemon-reload

echo "[*] Starter services..."
systemctl enable --now ospd-openvas.service || true
systemctl enable --now gvmd.service || true
systemctl enable --now gsad.service || true

echo "[*] Genstarter gsad..."
systemctl restart gsad

echo "[*] Starter hele GVM stack..."
gvm-start || true

echo "[*] Verificerer setup..."
gvm-check-setup || true

echo "[*] Åbner firewall hvis UFW er aktiv..."
if command -v ufw >/dev/null 2>&1; then
  ufw allow 9392/tcp || true
fi

echo "[*] Lytter gsad på:"
ss -tulpen | grep 9392 || true

IP_ADDR="$(hostname -I | awk '{print $1}')"

echo
echo "[+] Færdig!"
echo "[+] Web UI: https://${IP_ADDR}:9392"
echo "[+] Log: $LOG"
