#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - SOC Lab
# Event: File Modification
# ============================================================

echo
echo "============================================================"
echo "                   FILE MODIFICATION TEST"
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

TESTFILE="/etc/nordic-soc-test.conf"
TESTVALUE="SOC-LAB file modification $(date '+%Y-%m-%d %H:%M:%S')"

echo
echo "[*] Opretter/ændrer følgende fil på VulnSrv01:"
echo
echo "    $TESTFILE"
echo
echo "[*] Der foretages ingen ændringer i eksisterende systemfiler."
echo "[*] Du kan blive bedt om password."
echo

ssh -t \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "${USERNAME}@${TARGET}" \
    "echo '$TESTVALUE' | sudo tee -a '$TESTFILE' >/dev/null && sudo stat '$TESTFILE'"

RESULT=$?

echo

if [[ $RESULT -eq 0 ]]; then
    echo "[+] Filændringen blev gennemført."
    echo
    echo "Fil:"
    echo "  $TESTFILE"
    echo
    echo "Kontrollér filen på VulnSrv01 med:"
    echo
    echo "  sudo cat $TESTFILE"
    echo
    echo "eller:"
    echo
    echo "  sudo stat $TESTFILE"
else
    echo "[!] Filændringen blev ikke gennemført."
    echo "[!] Kontrollér SSH-login og sudo-rettigheder."
fi

echo
read -rp "Tryk ENTER for at fortsætte..."