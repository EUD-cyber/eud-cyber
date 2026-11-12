```bash
#!/bin/bash

set -e

NTP_VERSION="4.2.6p5"
INSTALL_DIR="/opt/ntp-${NTP_VERSION}"
CONFIG_DIR="${INSTALL_DIR}/etc"
CONFIG_FILE="${CONFIG_DIR}/ntp.conf"
SOURCE_URL="https://archive.ntp.org/ntp4/ntp-${NTP_VERSION}.tar.gz"

echo "========================================"
echo " Vulnerable NTP Server Lab"
echo " CVE-2013-5211"
echo " ntpd ${NTP_VERSION}"
echo "========================================"

if [ "$EUID" -ne 0 ]; then
    echo "Kør scriptet som root:"
    echo "sudo $0"
    exit 1
fi

echo
echo "[1/8] Installerer nødvendige pakker..."

apt update
apt install -y \
    build-essential \
    wget \
    curl \
    libssl-dev \
    libcap-dev \
    pkg-config

echo
echo "[2/8] Stopper eksisterende NTP-services..."

systemctl stop ntp 2>/dev/null || true
systemctl disable ntp 2>/dev/null || true

systemctl stop ntpsec 2>/dev/null || true
systemctl disable ntpsec 2>/dev/null || true

systemctl stop chrony 2>/dev/null || true
systemctl disable chrony 2>/dev/null || true

systemctl stop systemd-timesyncd 2>/dev/null || true

echo
echo "[3/8] Henter ntpd ${NTP_VERSION}..."

cd /tmp

rm -rf "ntp-${NTP_VERSION}"
rm -f "ntp-${NTP_VERSION}.tar.gz"

wget "${SOURCE_URL}"

tar xzf "ntp-${NTP_VERSION}.tar.gz"

cd "ntp-${NTP_VERSION}"

echo
echo "[4/8] Compiler ntpd..."

./configure \
    --prefix="${INSTALL_DIR}" \
    --sysconfdir="${CONFIG_DIR}"

make -j"$(nproc)"
make install

echo
echo "[5/8] Opretter konfiguration..."

mkdir -p "${CONFIG_DIR}"
mkdir -p /var/lib/ntp
touch /var/lib/ntp/ntp.drift

cat > "${CONFIG_FILE}" <<EOF
#
# ============================================================
# INTENTIONALLY VULNERABLE NTP CONFIGURATION
# Cyber Security Training Lab
#
# CVE-2013-5211
#
# DO NOT USE ON PRODUCTION OR INTERNET-FACING SYSTEMS
# ============================================================
#

driftfile /var/lib/ntp/ntp.drift

#
# Lokal clock så serveren kan fungere uden internet.
#
server 127.127.1.0
fudge 127.127.1.0 stratum 8

#
# CVE-2013-5211 LAB CONFIGURATION
#
# Monitor-funktionen er bevidst aktiveret.
#
enable monitor

#
# Query access er bevidst tilladt.
#
# Vi bruger IKKE:
#
#   noquery
#   disable monitor
#
# da disse ville mitigere CVE-2013-5211.
#

restrict default nomodify notrap
restrict 127.0.0.1

EOF

echo
echo "[6/8] Opretter systemd service..."

cat > /etc/systemd/system/vulnerable-ntpd.service <<EOF
[Unit]
Description=Vulnerable NTPD ${NTP_VERSION} - CyberLab CVE-2013-5211
After=network.target

[Service]
Type=forking
ExecStart=${INSTALL_DIR}/bin/ntpd -g -c ${CONFIG_FILE}
PIDFile=/var/run/ntpd.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vulnerable-ntpd.service
systemctl restart vulnerable-ntpd.service

sleep 2

echo
echo "[7/8] Kontrollerer installation..."

echo
echo "NTP-version:"
"${INSTALL_DIR}/bin/ntpd" --version || true

echo
echo "UDP port 123:"
ss -lunp | grep ':123' || true

echo
echo "Service status:"
systemctl --no-pager --full status vulnerable-ntpd.service || true

echo
echo "[8/8] Installation færdig."

IP=$(hostname -I | awk '{print $1}')

echo
echo "========================================"
echo " VULNERABLE NTP SERVER READY"
echo "========================================"
echo
echo "IP:             ${IP}"
echo "Service:        ntpd"
echo "Version:        ${NTP_VERSION}"
echo "Port:           UDP/123"
echo "CVE:            CVE-2013-5211"
echo "Monitor:        ENABLED"
echo "Mode 7 queries: ALLOWED"
echo
echo "Config:"
echo "${CONFIG_FILE}"
echo
echo "Binary:"
echo "${INSTALL_DIR}/bin/ntpd"
echo
echo "Test fra Kali:"
echo
echo "  nmap -sU -p 123 ${IP}"
echo
echo "  nmap -sU -p 123 --script ntp-info ${IP}"
echo
echo "========================================"
echo
echo "ADVARSEL:"
echo "Denne server er bevidst gjort sårbar."
echo "Den må kun bruges i et isoleret CyberLab."
echo "Eksponér IKKE UDP/123 mod internettet."
echo
```
