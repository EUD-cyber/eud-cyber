#!/usr/bin/env bash

# ============================================================
# Nordic Manufacturing A/S
# SOC Lab - Failed SSH Login Event
#
# Kører på: Kali
# Target:    VulnSrv01
#
# Formål:
# Genererer kontrollerede mislykkede SSH-loginforsøg,
# som efterfølgende kan findes og analyseres i Wazuh.
# ============================================================

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

clear

echo -e "${BLUE}"
echo "============================================================"
echo " Nordic Manufacturing A/S - SOC Lab"
echo " Failed SSH Login Event"
echo "============================================================"
echo -e "${NC}"

# ------------------------------------------------------------
# Target
# ------------------------------------------------------------

read -r -p "Indtast IP-adressen på VulnSrv01: " TARGET

if [[ -z "$TARGET" ]]; then
    echo -e "${RED}[!] Ingen IP-adresse angivet.${NC}"
    exit 1
fi

# Simpelt IPv4 format-check
if [[ ! "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo -e "${RED}[!] Ugyldigt IP-format.${NC}"
    exit 1
fi

# ------------------------------------------------------------
# Kontroller SSH
# ------------------------------------------------------------

if ! command -v ssh >/dev/null 2>&1; then
    echo -e "${RED}[!] SSH-klienten er ikke installeret.${NC}"
    exit 1
fi

# ------------------------------------------------------------
# Kontroller om port 22 kan nås
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Kontrollerer SSH på $TARGET...${NC}"

if timeout 3 bash -c "</dev/tcp/$TARGET/22" 2>/dev/null; then
    echo -e "${GREEN}[+] TCP/22 er åben.${NC}"
else
    echo -e "${RED}[!] Kan ikke forbinde til TCP/22 på $TARGET.${NC}"
    echo
    echo "Kontroller:"
    echo "  - IP-adressen"
    echo "  - at VulnSrv01 er startet"
    echo "  - at SSH-serveren kører"
    echo "  - firewall-regler"
    exit 1
fi

# ------------------------------------------------------------
# Opret unikt ugyldigt brugernavn
# ------------------------------------------------------------

TESTUSER="soc_test_$(date +%s)"

echo
echo "Testinformation:"
echo
echo "  Target : $TARGET"
echo "  Service: SSH"
echo "  User   : $TESTUSER"
echo "  Antal  : 3 mislykkede loginforsøg"

echo
read -r -p "Tryk Enter for at starte testen..."

# ------------------------------------------------------------
# Generer failed SSH events
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Genererer mislykkede SSH-loginforsøg...${NC}"
echo

for ATTEMPT in 1 2 3; do

    echo "    Forsøg $ATTEMPT/3"

    ssh \
        -o BatchMode=yes \
        -o PreferredAuthentications=publickey \
        -o PubkeyAuthentication=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        "${TESTUSER}@${TARGET}" \
        "exit" \
        >/dev/null 2>&1 || true

    sleep 2

done

# ------------------------------------------------------------
# Resultat
# ------------------------------------------------------------

echo
echo -e "${GREEN}[+] Testhændelser genereret.${NC}"

echo
echo "Der er sendt 3 mislykkede SSH-loginforsøg til:"
echo
echo "    $TARGET"

echo
echo -e "${YELLOW}Find nu hændelserne i Wazuh.${NC}"

echo
echo "Undersøg blandt andet:"
echo
echo "  - Hvilken agent/server registrerede hændelsen?"
echo "  - Hvornår skete den?"
echo "  - Hvilken bruger blev forsøgt anvendt?"
echo "  - Hvilken IP kom forbindelsen fra?"
echo "  - Hvilken service registrerede hændelsen?"
echo "  - Hvad var resultatet?"

echo
echo "Forventet:"
echo
echo "  Hændelsestype : Failed SSH authentication"
echo "  Bruger        : $TESTUSER"
echo "  Kilde         : Kali"
echo "  Destination   : $TARGET"
echo "  Resultat      : Login failed"

echo