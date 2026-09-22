#!/usr/bin/env bash

# ============================================================
# Nordic Manufacturing A/S
# SOC / SIEM Lab - Setup
# ============================================================

BASE_URL="https://raw.githubusercontent.com/EUD-cyber/eud-cyber/main/TESTFILES/SIEM"
INSTALL_DIR="/opt/nordic-soc-lab"
LAUNCHER="/usr/local/bin/soc-lab"

# ============================================================
# Filer
# ============================================================

FILES=(
    "soc-lab.sh"
    "events/failed-ssh.sh"
    "events/file-change.sh"
    "events/successful-ssh.sh"
    "events/sudo-activity.sh"
    "events/user-created.sh"
)

# ============================================================
# Nødvendige programmer
# Format: kommando:apt-pakke
# ============================================================

REQUIREMENTS=(
    "curl:curl"
    "wget:wget"
    "ssh:openssh-client"
    "nmap:nmap"
    "git:git"
)

# ============================================================
# Farver
# ============================================================

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

# ============================================================
# Banner
# ============================================================

clear

echo -e "${BLUE}"
echo "============================================================"
echo "       Nordic Manufacturing A/S - SOC Lab Setup"
echo "============================================================"
echo -e "${NC}"

# ============================================================
# Root check
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Setup skal køres som root.${NC}"
    echo
    echo "Kør:"
    echo
    echo "    sudo ./setup.sh"
    echo
    exit 1
fi

# ============================================================
# OS check
# ============================================================

echo -e "${BLUE}[*] Kontrollerer operativsystem...${NC}"

if [[ ! -f /etc/os-release ]]; then
    echo -e "${RED}[!] /etc/os-release blev ikke fundet.${NC}"
    exit 1
fi

source /etc/os-release

echo -e "${GREEN}[+] Fundet: ${PRETTY_NAME}${NC}"

if [[ "${ID:-}" != "kali" ]]; then

    echo
    echo -e "${YELLOW}[!] Systemet ser ikke ud til at være Kali Linux.${NC}"

    read -r -p "Vil du fortsætte alligevel? [y/N]: " ANSWER

    case "$ANSWER" in
        y|Y)
            ;;
        *)
            exit 1
            ;;
    esac
fi

# ============================================================
# Internet / GitHub check
# ============================================================

echo
echo -e "${BLUE}[*] Kontrollerer forbindelse til GitHub...${NC}"

if curl -fsSL \
    --connect-timeout 10 \
    "https://raw.githubusercontent.com" \
    >/dev/null 2>&1; then

    echo -e "${GREEN}[+] GitHub forbindelse OK.${NC}"

else

    echo -e "${RED}[!] GitHub kan ikke nås.${NC}"
    echo
    echo "Kontroller internetforbindelsen."
    exit 1

fi

# ============================================================
# Dependency check
# ============================================================

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

# ============================================================
# Installer manglende programmer
# ============================================================

if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then

    echo
    echo -e "${YELLOW}Følgende pakker mangler:${NC}"

    for PACKAGE in "${MISSING_PACKAGES[@]}"; do
        echo "    - $PACKAGE"
    done

    echo
    echo -e "${BLUE}[*] Opdaterer pakkeliste...${NC}"

    if ! apt-get update; then
        echo -e "${RED}[!] apt-get update fejlede.${NC}"
        exit 1
    fi

    echo
    echo -e "${BLUE}[*] Installerer manglende programmer...${NC}"

    if ! apt-get install -y "${MISSING_PACKAGES[@]}"; then
        echo -e "${RED}[!] Installation af pakker fejlede.${NC}"
        exit 1
    fi

    echo
    echo -e "${GREEN}[+] Programmer installeret.${NC}"

else

    echo
    echo -e "${GREEN}[+] Alle nødvendige programmer er installeret.${NC}"

fi

# ============================================================
# Opret installationsstruktur
# ============================================================

echo
echo -e "${BLUE}[*] Opretter SOC Lab mapper...${NC}"

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/events"
mkdir -p "$INSTALL_DIR/detection"
mkdir -p "$INSTALL_DIR/scenarios"

if [[ ! -d "$INSTALL_DIR" ]]; then
    echo -e "${RED}[!] Kunne ikke oprette $INSTALL_DIR${NC}"
    exit 1
fi

echo -e "${GREEN}[+] $INSTALL_DIR${NC}"

# ============================================================
# Download filer
# ============================================================

echo
echo -e "${BLUE}[*] Henter SOC Lab filer fra GitHub...${NC}"
echo

DOWNLOAD_ERROR=0
DOWNLOAD_COUNT=0

for FILE in "${FILES[@]}"; do

    URL="${BASE_URL}/${FILE}"
    DESTINATION="${INSTALL_DIR}/${FILE}"

    # Sørg for at undermappen eksisterer
    mkdir -p "$(dirname "$DESTINATION")"

    printf "    %-35s " "$FILE"

    if curl \
        -fsSL \
        --connect-timeout 10 \
        "$URL" \
        -o "$DESTINATION"; then

        # Kontrollér at filen ikke er tom
        if [[ -s "$DESTINATION" ]]; then

            chmod +x "$DESTINATION"

            echo -e "${GREEN}[OK]${NC}"

            ((DOWNLOAD_COUNT++))

        else

            echo -e "${RED}[TOM FIL]${NC}"

            rm -f "$DESTINATION"

            DOWNLOAD_ERROR=1

        fi

    else

        echo -e "${RED}[FEJL]${NC}"

        rm -f "$DESTINATION"

        DOWNLOAD_ERROR=1

    fi

done

# ============================================================
# Download status
# ============================================================

echo

echo -e "${BLUE}[*] Download status:${NC}"
echo
echo "    Downloadede filer: $DOWNLOAD_COUNT"
echo "    Forventede filer : ${#FILES[@]}"

if [[ $DOWNLOAD_ERROR -ne 0 ]]; then

    echo
    echo -e "${YELLOW}[!] En eller flere filer kunne ikke hentes.${NC}"
    echo
    echo "Kontroller GitHub:"
    echo
    echo "https://github.com/EUD-cyber/eud-cyber/tree/main/TESTFILES/SIEM"
    echo

fi

# ============================================================
# Permissions
# ============================================================

echo -e "${BLUE}[*] Kontrollerer execute permissions...${NC}"

find "$INSTALL_DIR" \
    -type f \
    -name "*.sh" \
    -exec chmod +x {} \;

echo -e "${GREEN}[+] Permissions OK.${NC}"

# ============================================================
# Opret soc-lab launcher
# ============================================================

echo
echo -e "${BLUE}[*] Opretter kommandoen soc-lab...${NC}"

if [[ -s "$INSTALL_DIR/soc-lab.sh" ]]; then

    ln -sf "$INSTALL_DIR/soc-lab.sh" "$LAUNCHER"

    chmod +x "$INSTALL_DIR/soc-lab.sh"

    if [[ -L "$LAUNCHER" ]]; then

        echo -e "${GREEN}[+] Launcher oprettet:${NC}"
        echo
        echo "    $LAUNCHER"
        echo "        -> $INSTALL_DIR/soc-lab.sh"

    else

        echo -e "${RED}[!] Kunne ikke oprette launcher.${NC}"

    fi

else

    echo -e "${RED}[!] soc-lab.sh mangler eller er tom.${NC}"
    echo "[!] Kommandoen soc-lab blev ikke oprettet."

    rm -f "$LAUNCHER"

fi

# ============================================================
# Vis installation
# ============================================================

echo
echo -e "${BLUE}[*] Installerede filer:${NC}"
echo

find "$INSTALL_DIR" \
    -type f \
    -printf "    %P\n" \
    | sort

# ============================================================
# Test launcher
# ============================================================

echo

if command -v soc-lab >/dev/null 2>&1; then

    echo -e "${GREEN}[+] soc-lab findes i PATH.${NC}"

else

    echo -e "${YELLOW}[!] soc-lab findes ikke i PATH.${NC}"

fi

# ============================================================
# Slut
# ============================================================

echo
echo -e "${BLUE}============================================================${NC}"

if [[ -s "$INSTALL_DIR/soc-lab.sh" ]]; then

    echo -e "${GREEN}       SOC Lab installation færdig${NC}"

else

    echo -e "${YELLOW}       SOC Lab installation ikke komplet${NC}"

fi

echo -e "${BLUE}============================================================${NC}"
echo

echo "Installation:"
echo
echo "    $INSTALL_DIR"
echo

if [[ -s "$INSTALL_DIR/soc-lab.sh" ]]; then

    echo "Start SOC Lab med:"
    echo
    echo "    soc-lab"
    echo

fi