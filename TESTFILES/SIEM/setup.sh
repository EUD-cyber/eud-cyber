bash
#!/usr/bin/env bash

# ============================================================
# Nordic Manufacturing A/S
# SOC / SIEM Lab - Kali Setup
# ============================================================

BASE_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/SIEM"
INSTALL_DIR="/opt/nordic-soc-lab"

# ------------------------------------------------------------
# Filer der skal hentes
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
# Programmer der skal være installeret
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

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------

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
    echo -e "${RED}[!] Setup skal køres som root.${NC}"
    echo
    echo "Kør:"
    echo
    echo "  sudo ./setup.sh"
    echo
    exit 1
fi

# ------------------------------------------------------------
# OS check
# ------------------------------------------------------------

echo -e "${BLUE}[*] Kontrollerer operativsystem...${NC}"

if [[ ! -f /etc/os-release ]]; then
    echo -e "${RED}[!] /etc/os-release blev ikke fundet.${NC}"
    exit 1
fi

source /etc/os-release

echo -e "${GREEN}[+] Fundet: ${PRETTY_NAME}${NC}"

if [[ "${ID:-}" != "kali" ]]; then
    echo
    echo -e "${YELLOW}[!] Dette system ser ikke ud til at være Kali Linux.${NC}"

    read -r -p "Vil du fortsætte alligevel? [y/N]: " ANSWER

    case "$ANSWER" in
        y|Y)
            ;;
        *)
            exit 1
            ;;
    esac
fi

# ------------------------------------------------------------
# Internet check
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Kontrollerer internetforbindelse...${NC}"

if ping -c 1 -W 3 github.com >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Internet/GitHub forbindelse OK.${NC}"
else
    echo -e "${YELLOW}[!] Ping til GitHub fejlede.${NC}"
    echo "[*] Tester HTTPS i stedet..."

    if curl -fsSL --connect-timeout 5 https://github.com >/dev/null 2>&1; then
        echo -e "${GREEN}[+] HTTPS forbindelse til GitHub OK.${NC}"
    else
        echo -e "${RED}[!] GitHub kan ikke nås.${NC}"
        exit 1
    fi
fi

# ------------------------------------------------------------
# Dependency check
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Kontrollerer nødvendige programmer...${NC}"

MISSING_PACKAGES=()

for ITEM in "${REQUIREMENTS[@]}"; do

    COMMAND="${ITEM%%:*}"
    PACKAGE="${ITEM##*:}"

    if command -v "$COMMAND" >/dev/null 2>&1; then

        echo -e "    ${GREEN}[OK]${NC} $COMMAND"

    else

        echo -e "    ${YELLOW}[MANGLER]${NC} $COMMAND"
        MISSING_PACKAGES+=("$PACKAGE")

    fi

done

# ------------------------------------------------------------
# Installer manglende programmer
# ------------------------------------------------------------

if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then

    echo
    echo -e "${YELLOW}Følgende pakker skal installeres:${NC}"

    for PACKAGE in "${MISSING_PACKAGES[@]}"; do
        echo "    - $PACKAGE"
    done

    echo
    echo -e "${BLUE}[*] Kører apt update...${NC}"

    if ! apt-get update; then
        echo -e "${RED}[!] apt update fejlede.${NC}"
        exit 1
    fi

    echo
    echo -e "${BLUE}[*] Installerer pakker...${NC}"

    if ! apt-get install -y "${MISSING_PACKAGES[@]}"; then
        echo -e "${RED}[!] Installation af pakker fejlede.${NC}"
        exit 1
    fi

    echo
    echo -e "${GREEN}[+] Manglende programmer er installeret.${NC}"

else

    echo
    echo -e "${GREEN}[+] Alle nødvendige programmer er installeret.${NC}"

fi

# ------------------------------------------------------------
# Opret installationsmappe
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Opretter installationsmappe...${NC}"

mkdir -p "$INSTALL_DIR"

if [[ ! -d "$INSTALL_DIR" ]]; then
    echo -e "${RED}[!] Kunne ikke oprette $INSTALL_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}[+] $INSTALL_DIR${NC}"

# ------------------------------------------------------------
# Download scripts
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Henter SOC Lab scripts...${NC}"
echo

DOWNLOAD_ERROR=0

for FILE in "${FILES[@]}"; do

    URL="${BASE_URL}/${FILE}"
    DESTINATION="${INSTALL_DIR}/${FILE}"

    printf "    %-25s " "$FILE"

    if curl -fsSL "$URL" -o "$DESTINATION"; then

        chmod +x "$DESTINATION"

        echo -e "${GREEN}[OK]${NC}"

    else

        echo -e "${RED}[FEJL]${NC}"

        rm -f "$DESTINATION"

        DOWNLOAD_ERROR=1

    fi

done

# ------------------------------------------------------------
# Kontroller download
# ------------------------------------------------------------

echo

if [[ $DOWNLOAD_ERROR -ne 0 ]]; then

    echo -e "${YELLOW}[!] En eller flere filer kunne ikke hentes.${NC}"
    echo
    echo "Kontroller filerne i:"
    echo
    echo "https://github.com/EUD-cyber/eud-cyber/tree/main/TESTFILES/SIEM"
    echo

fi

# ------------------------------------------------------------
# Opret soc-lab launcher
# ------------------------------------------------------------

if [[ -f "$INSTALL_DIR/soc-lab.sh" ]]; then

    echo -e "${BLUE}[*] Opretter kommandoen soc-lab...${NC}"

    chmod +x "$INSTALL_DIR/soc-lab.sh"

    ln -sf "$INSTALL_DIR/soc-lab.sh" /usr/local/bin/soc-lab

    if command -v soc-lab >/dev/null 2>&1; then

        echo -e "${GREEN}[+] Kommandoen soc-lab er oprettet.${NC}"

    else

        echo -e "${YELLOW}[!] Launcher blev oprettet, men findes ikke i PATH.${NC}"
        echo "    Brug: $INSTALL_DIR/soc-lab.sh"

    fi

else

    echo -e "${YELLOW}[!] soc-lab.sh blev ikke fundet.${NC}"
    echo "[!] Kommandoen soc-lab bliver derfor ikke oprettet."

fi

# ------------------------------------------------------------
# Vis installerede filer
# ------------------------------------------------------------

echo
echo -e "${BLUE}[*] Installerede filer:${NC}"
echo

ls -lh "$INSTALL_DIR"

# ------------------------------------------------------------
# Slutresultat
# ------------------------------------------------------------

echo
echo -e "${BLUE}============================================================${NC}"

if [[ -f "$INSTALL_DIR/soc-lab.sh" ]]; then

    echo -e "${GREEN}       SOC Lab installation færdig${NC}"

    echo -e "${BLUE}============================================================${NC}"

    echo
    echo "Start labben med:"
    echo
    echo "    soc-lab"
    echo
    echo "Installation:"
    echo
    echo "    $INSTALL_DIR"
    echo

else

    echo -e "${YELLOW}       Installation ikke komplet${NC}"

    echo -e "${BLUE}============================================================${NC}"

    echo
    echo "soc-lab.sh mangler."
    echo "Kontroller GitHub-filerne ovenfor."
    echo

fi
```
