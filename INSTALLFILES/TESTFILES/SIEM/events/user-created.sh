#!/bin/bash

# ============================================================
# Nordic Manufacturing A/S - SOC Lab
# Event: User Created
# ============================================================

echo
echo "============================================================"
echo "                     USER CREATED TEST"
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

# Unikt brugernavn, så testen kan køres flere gange
TESTUSER="soc_test_$(date +%H%M%S)"

echo
echo "[*] Opretter testbruger:"
echo
echo "    $TESTUSER"
echo
echo "[*] Kommando:"
echo "    sudo useradd -m $TESTUSER"
echo
echo "[*] Du kan blive bedt om password."
echo

ssh -t \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "${USERNAME}@${TARGET}" \
    "sudo useradd -m -s /bin/bash '$TESTUSER' && id '$TESTUSER'"

RESULT=$?

echo

if [[ $RESULT -eq 0 ]]; then
    echo "[+] Testbrugeren blev oprettet."
    echo
    echo "Bruger:"
    echo "  $TESTUSER"
    echo
    echo "Kontrollér på VulnSrv01 med:"
    echo
    echo "  getent passwd $TESTUSER"
    echo
    echo "Kontrollér authentication-loggen med:"
    echo
    echo "  sudo tail -50 /var/log/auth.log"
    echo
    echo "Se efter useradd og sudo-hændelser."
else
    echo "[!] Testbrugeren blev ikke oprettet."
    echo "[!] Kontrollér SSH-login og sudo-rettigheder."
fi

echo
read -rp "Tryk ENTER for at fortsætte..."