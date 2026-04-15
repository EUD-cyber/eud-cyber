#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Variables =====
WAZUH_MANAGER="192.168.2.20"
WAZUH_AGENT_NAME="vulnsrv01"

# 👉 CHANGE THIS when new version comes
WAZUH_AGENT_DEB="wazuh-agent_4.13.1-1_amd64.deb"
WAZUH_AGENT_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${WAZUH_AGENT_DEB}"

DATASET_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/WAZUH_LOGS/wazuh_soc_dataset_3months.zip"
WORKDIR="/opt/wazuh-dataset"
REPLAYDIR="/opt/wazuh-replay"

echo "=== STEP 1: Install Wazuh agent (ONE LINE style) ==="

curl -sO "$WAZUH_AGENT_URL" && \
sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" dpkg -i "$WAZUH_AGENT_DEB"

echo "=== STEP 2: Start agent ==="
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "=== Waiting for enrollment ==="
sleep 15

echo "=== Verify agent ==="
cat /var/ossec/etc/client.keys || true
tail -n 20 /var/ossec/logs/ossec.log || true

echo "=== STEP 3: Prepare dataset ==="
apt-get update -y
apt-get install -y unzip curl

mkdir -p "$WORKDIR" "$REPLAYDIR"

curl -L "$DATASET_URL" -o "$WORKDIR/dataset.zip"
unzip -o "$WORKDIR/dataset.zip" -d "$WORKDIR"

echo "=== STEP 4: Configure log sources ==="

cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak

cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <localfile>
    <log_format>syslog</log_format>
    <location>${REPLAYDIR}/auth.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>${REPLAYDIR}/apache_access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>${REPLAYDIR}/syslog.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>${REPLAYDIR}/suricata_eve.json</location>
  </localfile>
</ossec_config>
EOF

echo "=== Restart agent with new config ==="
systemctl restart wazuh-agent
sleep 5

echo "=== STEP 5: Prepare replay files ==="

: > "${REPLAYDIR}/auth.log"
: > "${REPLAYDIR}/apache_access.log"
: > "${REPLAYDIR}/syslog.log"
: > "${REPLAYDIR}/suricata_eve.json"

chmod 755 "$REPLAYDIR"
chmod 644 ${REPLAYDIR}/*

echo "=== STEP 6: Replay logs ==="

for file in auth.log apache_access.log syslog.log suricata_eve.json; do
  if [[ -f "${WORKDIR}/$file" ]]; then
    echo "[*] Replaying $file"
    while IFS= read -r line; do
      echo "$line" >> "${REPLAYDIR}/$file"
      sleep 0.005
    done < "${WORKDIR}/$file"
  fi
done

echo "=== DONE ==="
echo "Agent: ${WAZUH_AGENT_NAME}"
echo "Version file: ${WAZUH_AGENT_DEB}"
echo "Check: tail -f /var/ossec/logs/ossec.log"
