```bash
#!/usr/bin/env bash

# ============================================================
# Nordic Manufacturing A/S
# SOC / SIEM Lab - Kali Setup
# ============================================================

set -e

BASE_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/SIEM"
INSTALL_DIR="/opt/nordic-soc-lab"

# ------------------------------------------------------------
# Filer der skal hentes fra GitHub
# Tilføj de endelige scripts her.
# ------------------------------------------------------------

FILES=(
    "soc-lab.sh"
    "failed-ssh.sh"
    "successful-ssh.sh"
    "sudo-activity.sh"
    "user-created.sh"
    "file-change.sh"
)

# ------------------------------------------------------------
# Programmer som SOC-labben skal bruge
# format: kommando:apt-pakke
# ------------------------------------------------------------

REQUIREMENTS=(
    "curl:curl"
    "wget:wget"
    "ssh:openssh-client"
    "nmap:nmap"
    "git:git"
)

# ------------------------------------------------------------
# Farver
# ------------------------------------------------------------

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

clear

echo -e "${BLUE}"
echo "============================================================"
echo "       Nordic Manufacturing A/S - SOC Lab Setup"
echo "============================================================"
echo -e "${NC}"

# ------------------------------------------------------------
# Root check
# ------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Setup skal køres med sudo.${NC}"
    echo
    echo "Kør:"
    echo "sudo ./setup.sh"
    exit 1
fi

# ------------------------------------------------------------
# OS check
# ------------------------------------------------------------

echo -e "${BLUE}[*] Kontrollerer operativsystem...${NC}"

if [[ -f /etc/os-release ]]; then
    source /etc/os-release

    echo "[+] Fundet: $PRETTY_NAME"

    if [[ "${ID:-}" != "kali" ]]; then
        echo
        echo -e "${YELLOW}[!] Dette system ser ikke ud til at være Kali Linux.${NC}"
        read -r -p "Vil du fortsætte alligevel? [y/N]: " answer

        case "$answer" in
            y|Y)
                ;;
            *)
                exit 1
                ;;
        esac
    fi
else
    echo -e "${RED}[!] Kunne ikke identificere Linux distributionen.${NC}"
    exit 1
fi

# ------------------------------------------------------------
# Internet / GitHub test
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Tester forbindelse til GitHub...${NC}"

if curl -fsI --connect-timeout 5 \
    "https://raw.githubusercontent.com" >/dev/null; then

    echo -e "${GREEN}[+] GitHub kan nås.${NC}"

else
    echo -e "${RED}[!] Kan ikke nå GitHub.${NC}"
    echo "Kontroller internetforbindelsen."
    exit 1
fi

# ------------------------------------------------------------
# Dependency check
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Kontrollerer nødvendige programmer...${NC}"

MISSING_PACKAGES=()

for item in "${REQUIREMENTS[@]}"; do

    COMMAND="${item%%:*}"
    PACKAGE="${item##*:}"

    if command -v "$COMMAND" >/dev/null 2>&1; then

        echo -e "${GREEN}[OK]${NC} $COMMAND"

    else

        echo -e "${YELLOW}[MISSING]${NC} $COMMAND"
        MISSING_PACKAGES+=("$PACKAGE")

    fi

done

# ------------------------------------------------------------
# Installer manglende programmer
# ------------------------------------------------------------

if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then

    echo
    echo -e "${YELLOW}Følgende pakker mangler:${NC}"

    printf ' - %s\n' "${MISSING_PACKAGES[@]}"

    echo
    echo "[*] Installerer manglende pakker..."

    apt-get update
    apt-get install -y "${MISSING_PACKAGES[@]}"

    echo
    echo -e "${GREEN}[+] Programmer installeret.${NC}"

else

    echo
    echo -e "${GREEN}[+] Alle nødvendige programmer er installeret.${NC}"

fi

# ------------------------------------------------------------
# Opret installationsmappe
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Opretter SOC Lab mappe...${NC}"

mkdir -p "$INSTALL_DIR"

echo -e "${GREEN}[+] $INSTALL_DIR${NC}"

# ------------------------------------------------------------
# Download filer
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Henter SOC Lab filer fra GitHub...${NC}"

DOWNLOAD_ERROR=0

for FILE in "${FILES[@]}"; do

    echo -n "    $FILE ... "

    if curl -fsSL \
        "$BASE_URL/$FILE" \
        -o "$INSTALL_DIR/$FILE"; then

        echo -e "${GREEN}OK${NC}"

    else

        echo -e "${RED}FAILED${NC}"
        DOWNLOAD_ERROR=1

        # Fjern eventuel tom/ufuldstændig fil
        rm -f "$INSTALL_DIR/$FILE"

    fi

done

if [[ $DOWNLOAD_ERROR -ne 0 ]]; then

    echo
    echo -e "${YELLOW}[!] En eller flere filer kunne ikke hentes.${NC}"
    echo
    echo "Kontroller at filnavnene findes her:"
    echo "https://github.com/EUD-cyber/eud-cyber/tree/main/TESTFILES/SIEM"

fi

# ------------------------------------------------------------
# Gør scripts executable
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Sætter execute permissions...${NC}"

find "$INSTALL_DIR" \
    -maxdepth 1 \
    -type f \
    -name "*.sh" \
    -exec chmod +x {} \;

echo -e "${GREEN}[+] Permissions sat.${NC}"

# ------------------------------------------------------------
# Opret launcher
# ------------------------------------------------------------

if [[ -f "$INSTALL_DIR/soc-lab.sh" ]]; then

    echo
    echo -e "${BLUE}[*] Opretter kommandoen 'soc-lab'...${NC}"

    ln -sf "$INSTALL_DIR/soc-lab.sh" /usr/local/bin/soc-lab

    echo -e "${GREEN}[+] Launcher oprettet.${NC}"

fi

# ------------------------------------------------------------
# Resultat
# ------------------------------------------------------------

echo
echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN} SOC Lab installation færdig${NC}"
echo -e "${BLUE}============================================================${NC}"
echo

echo "Installeret i:"
echo
echo "  $INSTALL_DIR"
echo

echo "Filer:"
ls -1 "$INSTALL_DIR"

echo

if [[ -f "$INSTALL_DIR/soc-lab.sh" ]]; then

    echo "Start SOC Lab med:"
    echo
    echo "  soc-lab"
    echo
    echo "eller:"
    echo
    echo "  $INSTALL_DIR/soc-lab.sh"

fi

echo
```
