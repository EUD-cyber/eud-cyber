#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - SOC Lab
# Event: Sudo Activity
# ============================================================

echo
echo "============================================================"
echo "                    SUDO ACTIVITY TEST"
echo "============================================================"
echo

read -rp "VulnSrv01 IP: " TARGET

if [[ ! "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[!] Ugyldig IP-adresse."
    exit 1
fi

read -rp "SSH username på VulnSrv01: " USERNAME

if [[ -z "$USERNAME" ]]; then
    echo "[!] Brugernavn må ikke være tomt."
    exit 1
fi

echo
echo "[*] Kontrollerer SSH på $TARGET..."

if ! timeout 3 bash -c "</dev/tcp/$TARGET/22" 2>/dev/null; then
    echo "[!] Kan ikke forbinde til TCP/22 på $TARGET."
    exit 1
fi

echo "[+] SSH er tilgængelig."
echo
echo "[*] Opretter en kontrolleret sudo-hændelse på VulnSrv01."
echo "[*] Der køres kun kommandoen: sudo id"
echo
echo "[*] Du kan blive bedt om password."
echo

ssh -t \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "${USERNAME}@${TARGET}" \
    "sudo id"

RESULT=$?

echo

if [[ $RESULT -eq 0 ]]; then
    echo "[+] Sudo-hændelsen blev gennemført."
    echo
    echo "Kontrollér hændelsen på VulnSrv01 med:"
    echo
    echo "  sudo tail -50 /var/log/auth.log"
    echo
    echo "Se efter en linje med sudo og COMMAND=/usr/bin/id"
else
    echo "[!] Sudo-testen blev ikke gennemført."
    echo "[!] Kontrollér brugernavn, password og sudo-rettigheder."
fi

echo
read -rp "Tryk ENTER for at fortsætte..."