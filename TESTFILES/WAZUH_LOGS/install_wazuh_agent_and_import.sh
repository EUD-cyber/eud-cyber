#!/bin/bash
set -e

WAZUH_MANAGER="192.168.2.20"
DATASET_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/WAZUH_LOGS/wazuh_soc_dataset_3months.zip"
WORKDIR="/opt/wazuh-dataset"

echo "=== Installing Wazuh Agent ==="
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt update -y
apt install wazuh-agent -y

echo "=== Configuring agent ==="
sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER}<\/address>/" /var/ossec/etc/ossec.conf

echo "=== Setting agent name ==="
sed -i "s/<agent_name>.*<\/agent_name>/<agent_name>vuln-srv1<\/agent_name>/" /var/ossec/etc/ossec.conf || true

echo "=== Creating dataset directory ==="
mkdir -p $WORKDIR

echo "=== Downloading dataset ==="
curl -L "$DATASET_URL" -o $WORKDIR/dataset.zip

echo "=== Extracting dataset ==="
apt install unzip -y
unzip -o $WORKDIR/dataset.zip -d $WORKDIR

echo "=== Setting permissions ==="
chmod -R o+r $WORKDIR
chmod o+x $WORKDIR

echo "=== Adding log monitoring config ==="
cat <<EOF >> /var/ossec/etc/ossec.conf

<localfile>
  <log_format>syslog</log_format>
  <location>$WORKDIR/auth.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>$WORKDIR/apache_access.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>$WORKDIR/syslog.log</location>
</localfile>

<localfile>
  <log_format>json</log_format>
  <location>$WORKDIR/suricata_eve.json</location>
</localfile>

EOF

echo "=== Enabling and starting agent ==="
systemctl daemon-reexec
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "=== Waiting for agent to connect ==="
sleep 10

echo "=== Replaying logs ==="

# Auth logs
if [ -f "$WORKDIR/auth.log" ]; then
  while read -r line; do
    echo "$line" >> $WORKDIR/auth.log
    sleep 0.01
  done < $WORKDIR/auth.log
fi

# Apache logs
if [ -f "$WORKDIR/apache_access.log" ]; then
  while read -r line; do
    echo "$line" >> $WORKDIR/apache_access.log
    sleep 0.005
  done < $WORKDIR/apache_access.log
fi

# Syslog logs
if [ -f "$WORKDIR/syslog.log" ]; then
  while read -r line; do
    echo "$line" >> $WORKDIR/syslog.log
    sleep 0.005
  done < $WORKDIR/syslog.log
fi

echo "=== DONE ==="
echo "Check Wazuh dashboard → Security Events → filter by agent.name:vuln-srv1"
