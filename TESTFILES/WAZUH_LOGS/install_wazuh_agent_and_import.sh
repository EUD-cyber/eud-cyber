#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Variables =====
WAZUH_MANAGER="192.168.2.20"
WAZUH_REGISTRATION_SERVER="192.168.2.20"
WAZUH_AGENT_NAME="vulnsrv01"
WAZUH_AGENT_GROUP="default"
# Set only if your manager requires enrollment password:
WAZUH_REGISTRATION_PASSWORD=""

DATASET_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/WAZUH_LOGS/wazuh_soc_dataset_3months.zip"
WORKDIR="/opt/wazuh-dataset"
REPLAYDIR="/opt/wazuh-replay"
LOGFILE="/var/log/wazuh-agent-install.log"

exec > >(tee -a "$LOGFILE") 2>&1

echo "=== Starting Wazuh agent install ==="

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "=== Installing prerequisites ==="
apt-get update -y
apt-get install -y curl unzip gnupg apt-transport-https ca-certificates

echo "=== Adding Wazuh repository ==="
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 0644 /usr/share/keyrings/wazuh.gpg

cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF

apt-get update -y

echo "=== Testing connectivity to manager ==="
for port in 1514 1515; do
  if timeout 3 bash -c "</dev/tcp/${WAZUH_MANAGER}/${port}" 2>/dev/null; then
    echo "[+] Port ${port} reachable on ${WAZUH_MANAGER}"
  else
    echo "[!] Port ${port} NOT reachable on ${WAZUH_MANAGER}"
  fi
done

echo "=== Installing Wazuh agent with enrollment variables ==="
if [[ -n "${WAZUH_REGISTRATION_PASSWORD}" ]]; then
  WAZUH_MANAGER="${WAZUH_MANAGER}" \
  WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER}" \
  WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" \
  WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP}" \
  WAZUH_REGISTRATION_PASSWORD="${WAZUH_REGISTRATION_PASSWORD}" \
  apt-get install -y wazuh-agent
else
  WAZUH_MANAGER="${WAZUH_MANAGER}" \
  WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER}" \
  WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" \
  WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP}" \
  apt-get install -y wazuh-agent
fi

echo "=== Backing up agent config ==="
cp /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.bak.$(date +%F-%H%M%S)"

echo "=== Writing agent config ==="
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

echo "=== Validating config ==="
/var/ossec/bin/wazuh-agentd -t

echo "=== Preparing replay directories ==="
mkdir -p "$WORKDIR" "$REPLAYDIR"

echo "=== Downloading dataset ==="
curl -L "$DATASET_URL" -o "$WORKDIR/dataset.zip"

echo "=== Extracting dataset ==="
unzip -o "$WORKDIR/dataset.zip" -d "$WORKDIR"

echo "=== Preparing replay files ==="
: > "${REPLAYDIR}/auth.log"
: > "${REPLAYDIR}/apache_access.log"
: > "${REPLAYDIR}/syslog.log"
: > "${REPLAYDIR}/suricata_eve.json"

chmod 755 "$REPLAYDIR"
chmod 644 "${REPLAYDIR}/auth.log" "${REPLAYDIR}/apache_access.log" "${REPLAYDIR}/syslog.log" "${REPLAYDIR}/suricata_eve.json"

echo "=== Enabling and starting agent ==="
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "=== Waiting for enrollment/connection ==="
sleep 20

echo "=== Agent status ==="
systemctl --no-pager --full status wazuh-agent || true

echo "=== client.keys ==="
cat /var/ossec/etc/client.keys || true

echo "=== Recent ossec.log ==="
tail -n 50 /var/ossec/logs/ossec.log || true

echo "=== Replaying auth.log ==="
if [[ -f "${WORKDIR}/auth.log" ]]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/auth.log"
    sleep 0.01
  done < "${WORKDIR}/auth.log"
fi

echo "=== Replaying apache_access.log ==="
if [[ -f "${WORKDIR}/apache_access.log" ]]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/apache_access.log"
    sleep 0.005
  done < "${WORKDIR}/apache_access.log"
fi

echo "=== Replaying syslog.log ==="
if [[ -f "${WORKDIR}/syslog.log" ]]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/syslog.log"
    sleep 0.005
  done < "${WORKDIR}/syslog.log"
fi

echo "=== Replaying suricata_eve.json ==="
if [[ -f "${WORKDIR}/suricata_eve.json" ]]; then
  while IFS= read -r line; do
    echo "$line" >> "${REPLAYDIR}/suricata_eve.json"
    sleep 0.005
  done < "${WORKDIR}/suricata_eve.json"
fi

echo "=== DONE ==="
echo "Agent name: ${WAZUH_AGENT_NAME}"
echo "Manager: ${WAZUH_MANAGER}"
echo "Check logs with: tail -f /var/ossec/logs/ossec.log"
