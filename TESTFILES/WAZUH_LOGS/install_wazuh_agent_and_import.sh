#!/bin/bash
set -euo pipefail

WAZUH_MANAGER="192.168.2.20"
AGENT_NAME="vuln-srv1"
DATASET_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/WAZUH_LOGS/wazuh_soc_dataset_3months.zip"
WORKDIR="/opt/wazuh-dataset"
REPLAYDIR="/opt/wazuh-replay"

echo "=== Installing prerequisites ==="
apt update -y
apt install -y curl unzip gnupg apt-transport-https

echo "=== Installing Wazuh repository ==="
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

apt update -y
apt install -y wazuh-agent

echo "=== Creating directories ==="
mkdir -p "$WORKDIR" "$REPLAYDIR"

echo "=== Downloading dataset ==="
curl -L "$DATASET_URL" -o "$WORKDIR/dataset.zip"

echo "=== Extracting dataset ==="
unzip -o "$WORKDIR/dataset.zip" -d "$WORKDIR"

echo "=== Setting permissions ==="
chmod -R 755 "$WORKDIR" "$REPLAYDIR"

echo "=== Backing up current agent config ==="
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%F-%H%M%S)

echo "=== Writing valid Wazuh agent config ==="
cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu24, ubuntu24.04</config-profile>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

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

echo "=== Validating Wazuh config ==="
if ! /var/ossec/bin/wazuh-agentd -t; then
  echo "Wazuh config validation failed."
  exit 1
fi

echo "=== Preparing empty replay files ==="
: > "${REPLAYDIR}/auth.log"
: > "${REPLAYDIR}/apache_access.log"
: > "${REPLAYDIR}/syslog.log"
: > "${REPLAYDIR}/suricata_eve.json"
chown -R root:root "$REPLAYDIR"
chmod 644 "${REPLAYDIR}"/*

echo "=== Enabling and starting agent ==="
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "=== Waiting for agent startup ==="
sleep 10
systemctl --no-pager --full status wazuh-agent || true

echo "=== Replaying logs into fresh files ==="

if [ -f "${WORKDIR}/auth.log" ]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/auth.log"
    sleep 0.01
  done < "${WORKDIR}/auth.log"
fi

if [ -f "${WORKDIR}/apache_access.log" ]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/apache_access.log"
    sleep 0.005
  done < "${WORKDIR}/apache_access.log"
fi

if [ -f "${WORKDIR}/syslog.log" ]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/syslog.log"
    sleep 0.005
  done < "${WORKDIR}/syslog.log"
fi

if [ -f "${WORKDIR}/suricata_eve.json" ]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/suricata_eve.json"
    sleep 0.005
  done < "${WORKDIR}/suricata_eve.json"
fi

echo "=== DONE ==="
echo "Check Wazuh dashboard and filter by agent name: ${AGENT_NAME}"
echo "Local agent log:"
echo "  tail -f /var/ossec/logs/ossec.log"
