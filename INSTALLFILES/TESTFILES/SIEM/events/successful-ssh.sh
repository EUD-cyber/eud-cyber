#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - SOC Lab
# Event: Successful SSH Login
# ============================================================

echo
echo "============================================================"
echo "              SUCCESSFUL SSH LOGIN TEST"
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
echo "[*] Logger ind som $USERNAME@$TARGET"
echo "[*] Indtast brugerens password, hvis SSH spørger."
echo
echo "------------------------------------------------------------"

ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "${USERNAME}@${TARGET}" \
    'echo "SOC LAB - Successful SSH login"; hostname; whoami; date'

RESULT=$?

echo
echo "------------------------------------------------------------"

if [[ $RESULT -eq 0 ]]; then
    echo "[+] Successful SSH login gennemført."
    echo
    echo "Kontrollér nu VulnSrv01:"
    echo "  sudo tail -50 /var/log/auth.log"
else
    echo "[!] SSH-login blev ikke gennemført."
    echo "[!] Kontrollér brugernavn, password og SSH-konfiguration."
fi

echo
read -rp "Tryk ENTER for at fortsætte..."