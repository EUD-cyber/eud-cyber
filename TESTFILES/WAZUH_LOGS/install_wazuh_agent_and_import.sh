#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Variables =====
WAZUH_MANAGER="192.168.2.20"
WAZUH_AGENT_NAME="vulnsrv01"

# Must be <= manager version
WAZUH_AGENT_DEB="wazuh-agent_4.13.1-1_amd64.deb"
WAZUH_AGENT_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${WAZUH_AGENT_DEB}"

DATASET_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/WAZUH_LOGS/wazuh_soc_dataset_3months.zip"
WORKDIR="/opt/wazuh-dataset"
REPLAYDIR="/opt/wazuh-replay"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

echo "=== STEP 1: Install Wazuh agent ==="

curl -sO "$WAZUH_AGENT_URL" && \
sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" dpkg -i "$WAZUH_AGENT_DEB"

echo "=== STEP 2: Start agent ==="
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent

echo "=== Waiting for enrollment ==="
sleep 15

echo "=== Verify agent ==="
sudo cat /var/ossec/etc/client.keys || true
sudo tail -n 20 /var/ossec/logs/ossec.log || true

echo "=== STEP 3: Prepare dataset ==="
sudo apt-get update -y
sudo apt-get install -y unzip curl

sudo mkdir -p "$WORKDIR" "$REPLAYDIR"

sudo curl -L "$DATASET_URL" -o "$WORKDIR/dataset.zip"
sudo unzip -o "$WORKDIR/dataset.zip" -d "$WORKDIR"

echo "=== STEP 4: Prepare replay files first ==="
sudo touch "${REPLAYDIR}/auth.log"
sudo touch "${REPLAYDIR}/apache_access.log"
sudo touch "${REPLAYDIR}/syslog.log"
sudo touch "${REPLAYDIR}/suricata_eve.json"

sudo chmod 755 "$REPLAYDIR"
sudo chmod 644 "${REPLAYDIR}"/*

echo "=== STEP 5: Add logcollector config in the right place ==="

# Backup once
if [[ ! -f "${OSSEC_CONF}.bak" ]]; then
  sudo cp "$OSSEC_CONF" "${OSSEC_CONF}.bak"
fi

# Remove previously injected block if script is re-run
sudo sed -i '/<!-- WAZUH-REPLAY-BEGIN -->/,/<!-- WAZUH-REPLAY-END -->/d' "$OSSEC_CONF"

# Insert localfile entries before closing </ossec_config>
sudo awk '
  /<\/ossec_config>/ && !done {
    print "  <!-- WAZUH-REPLAY-BEGIN -->"
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>'"${REPLAYDIR}"'/auth.log</location>"
    print "  </localfile>"
    print ""
    print "  <localfile>"
    print "    <log_format>apache</log_format>"
    print "    <location>'"${REPLAYDIR}"'/apache_access.log</location>"
    print "  </localfile>"
    print ""
    print "  <localfile>"
    print "    <log_format>syslog</log_format>"
    print "    <location>'"${REPLAYDIR}"'/syslog.log</location>"
    print "  </localfile>"
    print ""
    print "  <localfile>"
    print "    <log_format>json</log_format>"
    print "    <location>'"${REPLAYDIR}"'/suricata_eve.json</location>"
    print "  </localfile>"
    print "  <!-- WAZUH-REPLAY-END -->"
    done=1
  }
  { print }
' "$OSSEC_CONF" | sudo tee "${OSSEC_CONF}.tmp" >/dev/null

sudo mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"

echo "=== STEP 6: Restart agent with updated config ==="
sudo systemctl restart wazuh-agent
sleep 5

echo "=== STEP 7: Show active localfile config ==="
sudo sed -n '/<!-- WAZUH-REPLAY-BEGIN -->/,/<!-- WAZUH-REPLAY-END -->/p' "$OSSEC_CONF" || true
sudo tail -n 30 /var/ossec/logs/ossec.log || true

echo "=== STEP 8: Replay logs ==="

for file in auth.log apache_access.log syslog.log suricata_eve.json; do
  if [[ -f "${WORKDIR}/$file" ]]; then
    echo "[*] Replaying $file"
    while IFS= read -r line; do
      echo "$line" | sudo tee -a "${REPLAYDIR}/$file" >/dev/null
      sleep 0.005
    done < "${WORKDIR}/$file"
  else
    echo "[!] Missing source file: ${WORKDIR}/$file"
  fi
done

echo "=== DONE ==="
echo "Agent: ${WAZUH_AGENT_NAME}"
echo "Version file: ${WAZUH_AGENT_DEB}"
echo "Check agent log: sudo tail -f /var/ossec/logs/ossec.log"
