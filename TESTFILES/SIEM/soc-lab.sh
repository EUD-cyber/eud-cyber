#!/usr/bin/env bash

# ============================================================
# Nordic Manufacturing A/S
# SOC / SIEM Lab
#
# Hovedmenu til generering af kontrollerede testhændelser.
#
# Installeres som:
#   /opt/nordic-soc-lab/soc-lab.sh
#
# Startes med:
#   soc-lab
# ============================================================

# ============================================================
# Find rigtig placering - også når scriptet køres via symlink
# ============================================================

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
BASE_DIR="$(dirname "$SCRIPT_PATH")"
EVENT_DIR="${BASE_DIR}/events"

# ============================================================
# Farver
# ============================================================

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

# ============================================================
# Funktioner
# ============================================================

pause_menu() {
    echo
    read -r -p "Tryk Enter for at vende tilbage til menuen..."
}

run_event() {

    local SCRIPT="$1"
    local SCRIPT_FILE="${EVENT_DIR}/${SCRIPT}"

    echo

    # Kontroller at filen eksisterer
    if [[ ! -f "$SCRIPT_FILE" ]]; then

        echo -e "${RED}[!] Event-scriptet findes ikke:${NC}"
        echo
        echo "    $SCRIPT_FILE"

        pause_menu
        return

    fi

    # Kontroller at filen ikke er tom
    if [[ ! -s "$SCRIPT_FILE" ]]; then

        echo -e "${RED}[!] Event-scriptet er tomt:${NC}"
        echo
        echo "    $SCRIPT_FILE"

        pause_menu
        return

    fi

    # Sørg for execute permission
    if [[ ! -x "$SCRIPT_FILE" ]]; then
        chmod +x "$SCRIPT_FILE"
    fi

    # Start event-script
    "$SCRIPT_FILE"

    pause_menu
}

show_header() {

    clear

    echo -e "${BLUE}"
    echo "============================================================"
    echo "             Nordic Manufacturing A/S"
    echo "                  SOC / SIEM LAB"
    echo "============================================================"
    echo -e "${NC}"

    echo "Kontrollerede sikkerhedshændelser til analyse i Wazuh."
    echo
    echo -e "${YELLOW}Kør kun testene mod CyberLab-miljøet.${NC}"
    echo
}

show_menu() {

    echo -e "${CYAN}EVENT GENERATION${NC}"
    echo
    echo "  [1] Failed SSH login"
    echo "  [2] Successful SSH login"
    echo "  [3] Sudo activity"
    echo "  [4] User created"
    echo "  [5] File modification"
    echo
    echo "  [0] Afslut"
    echo
}

# ============================================================
# Main
# ============================================================

while true; do

    show_header
    show_menu

    read -r -p "Vælg test: " CHOICE

    case "$CHOICE" in

        1)
            run_event "failed-ssh.sh"
            ;;

        2)
            run_event "successful-ssh.sh"
            ;;

        3)
            run_event "sudo-activity.sh"
            ;;

        4)
            run_event "user-created.sh"
            ;;

        5)
            run_event "file-change.sh"
            ;;

        0)
            clear
            echo
            echo -e "${GREEN}SOC Lab afsluttet.${NC}"
            echo
            exit 0
            ;;

        *)
            echo
            echo -e "${RED}[!] Ugyldigt valg.${NC}"
            sleep 1
            ;;

    esac

done