#!/bin/bash
set -e

# =========================================================
# CONFIG
# =========================================================
DATASET_URL="https://raw.githubusercontent.com/YOUR-USER/YOUR-REPO/main/wazuh_soc_dataset_3months.zip"
WORKDIR="/opt/wazuh-dataset"
ZIPFILE="/opt/wazuh_soc_dataset_3months.zip"
WAZUH_CONF="/var/ossec/etc/ossec.conf"
WAZUH_BACKUP="/var/ossec/etc/ossec.conf.bak"
SNIPPET_FILE="/tmp/wazuh-localfiles.xml"

# =========================================================
# CHECK ROOT
# =========================================================
if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root"
  exit 1
fi

echo "=== Installing required packages ==="
apt-get update
apt-get install -y unzip curl

echo "=== Creating work directory ==="
mkdir -p "$WORKDIR"

echo "=== Downloading dataset ==="
curl -L "$DATASET_URL" -o "$ZIPFILE"

echo "=== Extracting dataset ==="
unzip -o "$ZIPFILE" -d "$WORKDIR"

echo "=== Checking extracted files ==="
ls -lah "$WORKDIR"

# =========================================================
# CREATE WAZUH LOCALFILE BLOCK
# =========================================================
cat > "$SNIPPET_FILE" <<'EOF'
  <!-- Wazuh training dataset -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/wazuh-dataset/auth.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/opt/wazuh-dataset/apache_access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/wazuh-dataset/syslog.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/opt/wazuh-dataset/suricata_eve.json</location>
  </localfile>
EOF

echo "=== Backing up ossec.conf ==="
cp "$WAZUH_CONF" "$WAZUH_BACKUP"

echo "=== Removing old dataset block if it exists ==="
sed -i '/<!-- Wazuh training dataset -->/,/<\/localfile>/d' "$WAZUH_CONF" || true

# Clean repeated dataset blocks more safely
python3 - <<'PY'
from pathlib import Path
conf = Path("/var/ossec/etc/ossec.conf")
text = conf.read_text()

start_marker = "  <!-- Wazuh training dataset -->"
blocks = [
'''  <!-- Wazuh training dataset -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/wazuh-dataset/auth.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/opt/wazuh-dataset/apache_access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/opt/wazuh-dataset/syslog.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/opt/wazuh-dataset/suricata_eve.json</location>
  </localfile>
'''
]
for block in blocks:
    text = text.replace(block, "")
conf.write_text(text)
PY

echo "=== Inserting dataset config into ossec.conf ==="
python3 - <<'PY'
from pathlib import Path
conf = Path("/var/ossec/etc/ossec.conf")
snippet = Path("/tmp/wazuh-localfiles.xml").read_text()
text = conf.read_text()

closing_tag = "</ossec_config>"
if closing_tag not in text:
    raise SystemExit("Could not find </ossec_config> in ossec.conf")

text = text.replace(closing_tag, snippet + "\n" + closing_tag, 1)
conf.write_text(text)
PY

echo "=== Validating config ==="
if /var/ossec/bin/wazuh-analysisd -t; then
  echo "Wazuh config is valid"
else
  echo "Config test failed, restoring backup"
  cp "$WAZUH_BACKUP" "$WAZUH_CONF"
  exit 1
fi

echo "=== Restarting Wazuh manager ==="
systemctl restart wazuh-manager

echo "=== Status ==="
systemctl --no-pager --full status wazuh-manager | head -n 20

echo
echo "Done."
echo "Dataset path: $WORKDIR"
echo "Open Wazuh dashboard and set time filter to: Last 90 days or All time"
echo "Useful searches:"
echo "  data.program_name:sshd"
echo "  data.program_name:sudo"
echo "  data.event_type:alert"
echo "  data.src_ip:10.0.0.50"
