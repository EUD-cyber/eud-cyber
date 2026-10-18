#!/bin/bash

set -e

# ============================================================
# CyberLab Multi Deployment
#
# BASIC:
#   OPNsense
#   Guacamole
#   Kali01
#   VulnSrv01
#
# OPTIONAL:
#   VulnSrv02
#   Kali02
#   AppSrv01
#   Client01
#   Wazuh
#   T-Pot
#   MrNobody
# ============================================================


# ============================================================
# Script paths
# ============================================================

REPO="./repo.sh"
PREREQ="./pre_req.sh"

OPENVSWITCHPRE="./open-vswitch-pre.sh"
OPENVSWITCH="./open-vswitch.sh"
OPENVSWITCHLAST="./open-vswitch-last.sh"

OPNSENSE="./OPNSENSE/OPNSENSE_multi_installer.sh"
OPNSENSECONF="./OPNSENSE/generate_config_multi.sh"

GUACVM02="./GUACVM02/GUACVM02_installer.sh"
GUACVM02_IP="./GUACVM02/GUACVM02_ip.sh"

VULNSRV01="./VULNSRV01/VULNSRV01_multi_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_multi_installer.sh"

KALI01="./KALI01/KALI01_multi_installer.sh"
KALI02="./KALI02/KALI02_multi_installer.sh"

APPSRV01="./APPSRV01/APPSRV01_installer.sh"
CLIENT01="./CLIENT01/CLIENT01_installer.sh"

WAZUH="./WAZUH/WAZUH_multi_installer.sh"
TPOT="./TPOT01/TPOT01_multi_installer.sh"

IMAGESRV="./IMAGESRV/IMAGESRV_installer.sh"

MRNOBODY="./MRNOBODY/mrnobody_installer.sh"


# ============================================================
# Functions
# ============================================================

pause() {

    echo
    read -rp "Press ENTER to continue..."

}


# ============================================================
# SELECT NUMBER OF LABS
# ============================================================

select_lab_count() {

    clear

    echo "========================================"
    echo "       CyberLab Multi Installation"
    echo "========================================"
    echo

    while true; do

        read -rp "How many labs to prepare (1-16): " LABCOUNT

        if [[ "$LABCOUNT" =~ ^[0-9]+$ ]] && \
           [ "$LABCOUNT" -ge 1 ] && \
           [ "$LABCOUNT" -le 16 ]; then

            break

        fi

        echo
        echo "Invalid number. Must be between 1 and 16."
        echo

    done

    echo
    echo "========================================"
    echo " Preparing $LABCOUNT lab(s)"
    echo "========================================"
    echo

    sleep 2
}


# ============================================================
# WHIPTAIL
# ============================================================

check_whiptail() {

    if ! command -v whiptail >/dev/null 2>&1; then

        echo "Installing whiptail..."

        apt-get update
        apt-get install -y whiptail

    fi
}


# ============================================================
# OPTIONAL COMPONENT SELECTION
# ============================================================

select_optional_components() {

    check_whiptail

    OPTIONS=$(whiptail \
        --title "CyberLab - Optional Components" \
        --checklist \
"Preparing $LABCOUNT lab(s)

Basic installation always includes:

  OPNsense
  Guacamole
  Kali01
  VulnSrv01

Select additional systems:

UP/DOWN = Move
SPACE   = Select
ENTER   = Continue" \
        27 78 12 \
        "VULNSRV02"   "Vulnerable Server 02"          OFF \
        "KALI02"      "Secondary Kali attacker"       OFF \
        "APPSRV01"    "Security Application Server"   OFF \
        "CLIENT01"    "Ubuntu Client"                 OFF \
        "WAZUH"       "Wazuh SIEM"                    OFF \
        "TPOT"        "T-Pot Honeypot"                OFF \
        "MRNOBODY"    "MrNobody Attack VM"            OFF \
        3>&1 1>&2 2>&3)

    STATUS=$?

    if [ "$STATUS" -ne 0 ]; then

        echo
        echo "Installation cancelled."

        return 1

    fi
}


# ============================================================
# OPNsense CONFIGURATION
# ============================================================

configure_opnsense() {

    clear

    echo "========================================"
    echo "       OPNsense Configuration"
    echo "========================================"
    echo
    echo "Labs: $LABCOUNT"
    echo
    echo "Configure OPNsense before deployment."
    echo

    bash "$OPNSENSECONF" "$LABCOUNT"

    echo
    echo "OPNsense configuration completed."

    sleep 2
}


# ============================================================
# GUACAMOLE CONFIGURATION
# ============================================================

configure_guacamole() {

    clear

    echo "========================================"
    echo "       Guacamole Configuration"
    echo "========================================"
    echo
    echo "Labs: $LABCOUNT"
    echo
    echo "Configure Guacamole before deployment."
    echo

    bash "$GUACVM02_IP" "$LABCOUNT"

    echo
    echo "Guacamole configuration completed."

    sleep 2
}


# ============================================================
# PREREQUISITES
# ============================================================

install_prerequisites() {

    echo
    echo "========================================"
    echo " Proxmox prerequisites"
    echo "========================================"

    echo
    echo "[1/2] Configuring Proxmox repository..."

    bash "$REPO"

    echo
    echo "[2/2] Installing packages and snippets..."

    bash "$PREREQ"
}


# ============================================================
# OPEN VSWITCH
# ============================================================

install_openvswitch() {

    echo
    echo "========================================"
    echo " Open vSwitch - $LABCOUNT lab(s)"
    echo "========================================"

    bash "$OPENVSWITCHPRE"

    bash "$OPENVSWITCH" "$LABCOUNT"

    bash "$OPENVSWITCHLAST"
}


# ============================================================
# BUILD OPTIONAL TMUX COMMANDS
# ============================================================

build_optional_commands() {

    OPTIONAL_COMMANDS=""

    if [ -z "$OPTIONS" ]; then
        return
    fi

    for COMPONENT in $OPTIONS; do

        COMPONENT=$(echo "$COMPONENT" | tr -d '"')

        case "$COMPONENT" in

            VULNSRV02)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating VulnSrv02'
echo '========================================'
bash '$VULNSRV02' '$LABCOUNT'
"
                ;;


            KALI02)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating Kali02'
echo '========================================'
bash '$KALI02' '$LABCOUNT'
"
                ;;


            APPSRV01)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating AppSrv01'
echo '========================================'
bash '$APPSRV01' '$LABCOUNT'
"
                ;;


            CLIENT01)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating Client01'
echo '========================================'
bash '$CLIENT01' '$LABCOUNT'
"
                ;;


            WAZUH)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating Wazuh'
echo '========================================'
bash '$WAZUH' '$LABCOUNT'
"
                ;;


            TPOT)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating T-Pot'
echo '========================================'
bash '$TPOT' '$LABCOUNT'
"
                ;;


            MRNOBODY)

                OPTIONAL_COMMANDS+="
echo
echo '========================================'
echo ' Creating MrNobody'
echo '========================================'
bash '$MRNOBODY' '$LABCOUNT'
"
                ;;

        esac

    done
}


# ============================================================
# START TMUX DEPLOYMENT
# ============================================================

start_tmux_deployment() {

    SESSION="deploy-all"
    LOGFILE="deploy.log"


    # --------------------------------------------------------
    # Make sure tmux exists
    # --------------------------------------------------------

    if ! command -v tmux >/dev/null 2>&1; then

        echo
        echo "tmux not installed."
        echo "Installing tmux..."

        apt-get update
        apt-get install -y tmux

    fi


    # --------------------------------------------------------
    # Remove old session
    # --------------------------------------------------------

    if tmux has-session -t "$SESSION" 2>/dev/null; then

        echo
        echo "Old tmux session '$SESSION' found."
        echo "Stopping old session..."

        tmux kill-session -t "$SESSION"

    fi


    # --------------------------------------------------------
    # Build optional commands
    # --------------------------------------------------------

    build_optional_commands


    # --------------------------------------------------------
    # Clear old log
    # --------------------------------------------------------

    : > "$LOGFILE"


    # --------------------------------------------------------
    # Start tmux
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Starting background deployment"
    echo "========================================"
    echo
    echo "Labs: $LABCOUNT"
    echo


    tmux new-session -d -s "$SESSION" bash -c "

set -e

exec > >(tee -a '$LOGFILE') 2>&1


echo
echo '========================================'
echo ' CyberLab background deployment'
echo '========================================'
echo
echo 'Number of labs: $LABCOUNT'
echo


# ============================================================
# GUACAMOLE
# ============================================================

echo
echo '========================================'
echo ' Creating Guacamole - $LABCOUNT lab(s)'
echo '========================================'

bash '$GUACVM02' '$LABCOUNT'


# ============================================================
# KALI01
# ============================================================

echo
echo '========================================'
echo ' Creating Kali01 - $LABCOUNT lab(s)'
echo '========================================'

bash '$KALI01' '$LABCOUNT'


# ============================================================
# VULNSRV01
# ============================================================

echo
echo '========================================'
echo ' Creating VulnSrv01 - $LABCOUNT lab(s)'
echo '========================================'

bash '$VULNSRV01' '$LABCOUNT'


# ============================================================
# OPTIONAL COMPONENTS
# ============================================================

$OPTIONAL_COMMANDS


# ============================================================
# DONE
# ============================================================

echo
echo '========================================'
echo ' CYBERLAB DEPLOYMENT COMPLETED'
echo '========================================'
echo
echo '$LABCOUNT lab(s) prepared.'
echo 'All selected VMs have been installed.'
echo

"


    echo
    echo "========================================"
    echo " Deployment running in background"
    echo "========================================"
    echo
    echo "Labs: $LABCOUNT"
    echo
    echo "tmux session:"
    echo
    echo "  $SESSION"
    echo
    echo "Attach:"
    echo
    echo "  tmux attach -t $SESSION"
    echo
    echo "Detach without stopping:"
    echo
    echo "  CTRL+B then D"
    echo
    echo "Follow deployment log:"
    echo
    echo "  tail -f $LOGFILE"
    echo
}


# ============================================================
# FULL CYBERLAB MULTI INSTALLATION
# ============================================================

custom_install() {

    # ========================================================
    # STEP 1
    # Number of labs
    # ========================================================

    select_lab_count


    # ========================================================
    # STEP 2
    # Optional components
    # ========================================================

    select_optional_components || return


    # ========================================================
    # STEP 3
    # OPNsense configuration
    # ========================================================

    configure_opnsense


    # ========================================================
    # STEP 4
    # Guacamole configuration
    # ========================================================

    configure_guacamole


    # ========================================================
    # STEP 5
    # Summary
    # ========================================================

    clear

    echo "========================================"
    echo "       CyberLab Deployment"
    echo "========================================"
    echo
    echo "Number of labs: $LABCOUNT"
    echo
    echo "BASIC:"
    echo
    echo "  OPNsense"
    echo "  Guacamole"
    echo "  Kali01"
    echo "  VulnSrv01"
    echo
    echo "OPTIONAL:"

    if [ -n "$OPTIONS" ]; then

        for COMPONENT in $OPTIONS; do

            COMPONENT=$(echo "$COMPONENT" | tr -d '"')

            echo "  $COMPONENT"

        done

    else

        echo "  None"

    fi

    echo
    echo "========================================"
    echo "Labs:                     $LABCOUNT"
    echo "OPNsense configuration:   DONE"
    echo "Guacamole configuration:  DONE"
    echo "========================================"
    echo

    sleep 3


    # ========================================================
    # STEP 6
    # Prerequisites
    # ========================================================

    install_prerequisites


    # ========================================================
    # STEP 7
    # Open vSwitch
    # ========================================================

    install_openvswitch


    # ========================================================
    # STEP 8
    # OPNsense installs in foreground
    # ========================================================

    echo
    echo "========================================"
    echo " Installing OPNsense"
    echo "========================================"
    echo
    echo "Number of labs: $LABCOUNT"
    echo

    bash "$OPNSENSE" "$LABCOUNT"


    echo
    echo "========================================"
    echo " OPNsense installation completed"
    echo "========================================"
    echo


    # ========================================================
    # STEP 9
    # Everything else continues in tmux
    # ========================================================

    start_tmux_deployment
}


# ============================================================
# RUN SINGLE/MULTI COMPONENT
# ============================================================

run_component() {

    local NAME="$1"
    local SCRIPT="$2"

    select_lab_count

    echo
    echo "========================================"
    echo " Installing $NAME"
    echo "========================================"
    echo
    echo "Number of labs: $LABCOUNT"
    echo

    bash "$SCRIPT" "$LABCOUNT"
}


# ============================================================
# MAIN MENU
# ============================================================

while true; do

    clear

    echo "========================================"
    echo "       Proxmox Deployment Menu"
    echo "========================================"
    echo
    echo "--------- INSTALL ----------------------"
    echo
    echo "90) CyberLab Multi - Basic + Optional"
    echo
    echo "--------- BASIC ------------------------"
    echo
    echo "1)  Check packages & snippets"
    echo "2)  Install & configure Open vSwitch"
    echo "3)  Create OPNsense VM(s)"
    echo "4)  Create Guacamole VM(s)"
    echo "5)  Create VulnSrv01 VM(s)"
    echo "7)  Create Kali01 VM(s)"
    echo
    echo "--------- OPTIONAL ---------------------"
    echo
    echo "6)  Create VulnSrv02 VM(s)"
    echo "8)  Create Kali02 VM(s)"
    echo "9)  Create AppSrv01 VM(s)"
    echo "10) Create Client01 VM(s)"
    echo "11) Create Wazuh VM(s)"
    echo "12) Create T-Pot VM(s)"
    echo
    echo "--------- OTHER ------------------------"
    echo
    echo "80) Create Image Server VM"
    echo "89) Change Proxmox repo"
    echo "99) Cleanup installation files"
    echo "666) Create MrNobody VM(s)"
    echo
    echo "0) Exit"
    echo
    echo "========================================"

    read -rp "Enter your choice: " CHOICE


    case "$CHOICE" in


        1)

            bash "$PREREQ"

            pause

            ;;


        2)

            select_lab_count

            install_openvswitch

            pause

            ;;


        3)

            select_lab_count

            configure_opnsense

            bash "$OPNSENSE" "$LABCOUNT"

            pause

            ;;


        4)

            select_lab_count

            configure_guacamole

            bash "$GUACVM02" "$LABCOUNT"

            pause

            ;;


        5)

            run_component "VulnSrv01" "$VULNSRV01"

            pause

            ;;


        6)

            run_component "VulnSrv02" "$VULNSRV02"

            pause

            ;;


        7)

            run_component "Kali01" "$KALI01"

            pause

            ;;


        8)

            run_component "Kali02" "$KALI02"

            pause

            ;;


        9)

            run_component "AppSrv01" "$APPSRV01"

            pause

            ;;


        10)

            run_component "Client01" "$CLIENT01"

            pause

            ;;


        11)

            run_component "Wazuh" "$WAZUH"

            pause

            ;;


        12)

            run_component "T-Pot" "$TPOT"

            pause

            ;;


        80)

            bash "$IMAGESRV" "99"

            pause

            ;;


        89)

            bash "$REPO"

            pause

            ;;


        # ====================================================
        # MAIN MULTI INSTALL
        # ====================================================

        90)

            custom_install

            pause

            ;;


        99)

            rm -rf ./eud-cyber
            rm -rf /var/lib/vz/snippets/*
            rm -rf /var/lib/vz/template/iso/*

            echo
            echo "Cleanup completed."

            pause

            ;;


        666)

            run_component "MrNobody" "$MRNOBODY"

            pause

            ;;


        0)

            echo "Exiting."

            exit 0

            ;;


        *)

            echo "Invalid choice."

            sleep 2

            ;;

    esac

done