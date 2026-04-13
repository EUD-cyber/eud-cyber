#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-192.168.1.210}"

echo "[*] Starter demo mod $TARGET"
echo

echo "[1/5] TCP portscan"
nmap -sT -Pn -T4 -p 21,22,23,25,80,110,139,143,443,445,993,995,3306,3389 "$TARGET"

echo
echo "[2/5] Service detection"
nmap -sT -Pn -sV -p 21,22,23,80,445,3306,3389 "$TARGET"

echo
echo "[3/5] Banner grabbing"
for port in 21 22 23 25 80 110 139 143 443 445 3306 3389; do
  echo "---- Port $port ----"
  timeout 3 bash -c "echo | nc -nv $TARGET $port" || true
  echo
done

echo
echo "[4/5] Web requests"
curl -k -I --max-time 5 "http://$TARGET" || true
curl -k -I --max-time 5 "https://$TARGET" || true
curl -k --max-time 5 "http://$TARGET/login" || true
curl -k --max-time 5 "http://$TARGET/admin" || true
curl -k --max-time 5 "http://$TARGET/.env" || true

echo
echo "[5/5] Simulerede loginforsøg"
for user in admin root test ubuntu; do
  for pass in admin 123456 password Password1! toor; do
    echo "Tester SSH med $user / $pass"
    timeout 5 sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=3 \
      "$user@$TARGET" "exit" || true
  done
done

echo
echo "[*] Demo færdig. Tjek nu T-Pot dashboards og logs."
