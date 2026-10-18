#!/bin/bash
set -e

# ============================================================
# CyberLab Deployment
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
#   PacketFence
#   MrNobody
# ============================================================

LAB="1"

# ============================================================
# Script paths
# ============================================================

REPO="./repo.sh"
PREREQ="./pre_req.sh"

OPENVSWITCHPRE="./open-vswitch-multi-pre.sh"
OPENVSWITCH="./open-vswitch-multi.sh"
OPENVSWITCHLAST="./open-vswitch-multi-last.sh"

OPNSENSE="./OPNSENSE/OPNSENSE_multi_installer.sh"
OPNSENSECONF="./OPNSENSE/generate_config_multi.sh"

GUACVM02="./GUACVM02/GUACVM02_installer.sh"
GUACVM02_IP="./GUACVM02/GUACVM02_ip.sh"

VULNSRV01="./VULNSRV01/VULNSRV01_multi_installer.sh"
VULNSRV02="./VULNSRV02/VULNSRV02_multi_installer.sh"

KALI01="./KALI01/KALI01_multi_installer.sh"
KALI02="./KALI02/KALI02_multi_installer.sh"

APPSRV01="./APPSRV01/APPSRV01_multi_installer.sh"
CLIENT01="./CLIENT01/CLIENT01_multi_installer.sh"

WAZUH="./WAZUH/WAZUH_multi_installer.sh"
TPOT="./TPOT01/TPOT01_multi_installer.sh"

PACKETFENCE="./PACKETFENCE/PACKETFENCE_installer.sh"

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
"Basic installation always includes:

  OPNsense
  Guacamole
  Kali01
  VulnSrv01

Select additional systems:

UP/DOWN = Move
SPACE   = Select
ENTER   = Continue" \
        25 78 12 \
        "VULNSRV02"   "Vulnerable Server 02"          OFF \
        "KALI02"      "Secondary Kali attacker"       OFF \
        "APPSRV01"    "Security Application Server"   OFF \
        "CLIENT01"    "Ubuntu Client"                 OFF \
        "WAZUH"       "Wazuh SIEM"                    OFF \
        "TPOT"        "T-Pot Honeypot"                OFF \
        "PACKETFENCE" "PacketFence NAC"               OFF \
        "MRNOBODY"    "MrNobody Attack VM"            OFF \
        3>&1 1>&2 2>&3)

    STATUS=$?

    if [ "$STATUS" -ne 0 ]; then

        echo
        echo "Installation cancelled."

        exit 0
    fi
}


# ============================================================
# PRE CONFIGURATION
# ============================================================

configure_opnsense() {

    clear

    echo "========================================"
    echo "       OPNsense Configuration"
    echo "========================================"
    echo
    echo "Configure OPNsense before deployment."
    echo

    bash "$OPNSENSECONF" "$LAB"

    echo
    echo "OPNsense configuration completed."

    sleep 2
}


configure_guacamole() {

    clear

    echo "========================================"
    echo "       Guacamole Configuration"
    echo "========================================"
    echo
    echo "Configure Guacamole before deployment."
    echo

    bash "$GUACVM02_IP" "$LAB"

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
    echo " Open vSwitch"
    echo "========================================"

    bash "$OPENVSWITCHPRE"

    bash "$OPENVSWITCH" "$LAB"

    bash "$OPENVSWITCHLAST"
}


# ============================================================
# BASIC INSTALLATION
# ============================================================

install_basic() {

    echo
    echo "========================================"
    echo " BASIC CYBERLAB INSTALLATION"
    echo "========================================"
    echo
    echo "Lab: $LAB"
    echo
    echo "Installing:"
    echo
    echo "  OPNsense"
    echo "  Guacamole"
    echo "  Kali01"
    echo "  VulnSrv01"
    echo
    echo "========================================"


    # --------------------------------------------------------
    # Repository / prerequisites
    # --------------------------------------------------------

    install_prerequisites


    # --------------------------------------------------------
    # Open vSwitch
    # --------------------------------------------------------

    install_openvswitch


    # --------------------------------------------------------
    # OPNsense
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Creating OPNsense"
    echo "========================================"

    bash "$OPNSENSE" "$LAB"


    # --------------------------------------------------------
    # Guacamole
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Creating Guacamole"
    echo "========================================"

    bash "$GUACVM02" "$LAB"


    # --------------------------------------------------------
    # Kali01
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Creating Kali01"
    echo "========================================"

    bash "$KALI01" "$LAB"


    # --------------------------------------------------------
    # VulnSrv01
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Creating VulnSrv01"
    echo "========================================"

    bash "$VULNSRV01" "$LAB"


    echo
    echo "========================================"
    echo " BASIC INSTALLATION COMPLETED"
    echo "========================================"
}


# ============================================================
# OPTIONAL INSTALLATION
# ============================================================

install_optional_components() {

    if [ -z "$OPTIONS" ]; then

        echo
        echo "No optional components selected."

        return
    fi


    echo
    echo "========================================"
    echo " OPTIONAL COMPONENTS"
    echo "========================================"


    for COMPONENT in $OPTIONS; do

        COMPONENT=$(echo "$COMPONENT" | tr -d '"')


        case "$COMPONENT" in


            VULNSRV02)

                echo
                echo "========================================"
                echo " Creating VulnSrv02"
                echo "========================================"

                bash "$VULNSRV02" "$LAB"

                ;;


            KALI02)

                echo
                echo "========================================"
                echo " Creating Kali02"
                echo "========================================"

                bash "$KALI02" "$LAB"

                ;;


            APPSRV01)

                echo
                echo "========================================"
                echo " Creating AppSrv01"
                echo "========================================"

                bash "$APPSRV01" "$LAB"

                ;;


            CLIENT01)

                echo
                echo "========================================"
                echo " Creating Client01"
                echo "========================================"

                bash "$CLIENT01" "$LAB"

                ;;


            WAZUH)

                echo
                echo "========================================"
                echo " Creating Wazuh"
                echo "========================================"

                bash "$WAZUH" "$LAB"

                ;;


            TPOT)

                echo
                echo "========================================"
                echo " Creating T-Pot"
                echo "========================================"

                bash "$TPOT" "$LAB"

                ;;


            PACKETFENCE)

                echo
                echo "========================================"
                echo " Creating PacketFence"
                echo "========================================"

                bash "$PACKETFENCE" "$LAB"

                ;;


            MRNOBODY)

                echo
                echo "========================================"
                echo " Creating MrNobody"
                echo "========================================"

                bash "$MRNOBODY" "$LAB"

                ;;

        esac

    done
}


# ============================================================
# CYBERLAB INSTALLATION
# ============================================================

custom_install() {

    clear

    echo "========================================"
    echo "       CyberLab Installation"
    echo "========================================"
    echo
    echo "Basic installation:"
    echo
    echo "  OPNsense"
    echo "  Guacamole"
    echo "  Kali01"
    echo "  VulnSrv01"
    echo
    echo "You can now select optional systems."
    echo

    sleep 2


    # ========================================================
    # STEP 1
    # Select optional VMs
    # ========================================================

    select_optional_components


    # ========================================================
    # STEP 2
    # Configure OPNsense
    # ========================================================

    configure_opnsense


    # ========================================================
    # STEP 3
    # Configure Guacamole
    # ========================================================

    configure_guacamole


    # ========================================================
    # STEP 4
    # Show deployment summary
    # ========================================================

    clear

    echo "========================================"
    echo "       CyberLab Deployment"
    echo "========================================"
    echo
    echo "Lab: $LAB"
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
    echo
    echo "OPNsense configuration:  DONE"
    echo "Guacamole configuration: DONE"
    echo
    echo "========================================"
    echo


    # ========================================================
    # STEP 5
    # Start automatically
    # ========================================================

    echo "Starting CyberLab deployment..."
    echo

    sleep 3


    # ========================================================
    # STEP 6
    # Basic installation
    # ========================================================

    install_basic


    # ========================================================
    # STEP 7
    # Optional installation
    # ========================================================

    install_optional_components


    # ========================================================
    # DONE
    # ========================================================

    echo
    echo "========================================"
    echo "       DEPLOYMENT COMPLETED"
    echo "========================================"
    echo
    echo "Basic:"
    echo
    echo "  OPNsense       OK"
    echo "  Guacamole      OK"
    echo "  Kali01         OK"
    echo "  VulnSrv01      OK"
    echo

    if [ -n "$OPTIONS" ]; then

        echo "Optional:"

        for COMPONENT in $OPTIONS; do

            COMPONENT=$(echo "$COMPONENT" | tr -d '"')

            echo "  $COMPONENT      OK"

        done

    fi

    echo
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
    echo "Lab: $LAB"
    echo
    echo "--------- INSTALL ----------------------"
    echo
    echo "90) CyberLab Basic + Optional"
    echo
    echo "--------- BASIC ------------------------"
    echo
    echo "1)  Check packages & snippets"
    echo "2)  Install & configure Open vSwitch"
    echo "3)  Create OPNsense VM"
    echo "4)  Create Guacamole VM"
    echo "5)  Create VulnSrv01 VM"
    echo "7)  Create Kali01 VM"
    echo
    echo "--------- OPTIONAL ---------------------"
    echo
    echo "6)  Create VulnSrv02 VM"
    echo "8)  Create Kali02 VM"
    echo "9)  Create AppSrv01 VM"
    echo "10) Create Client01 VM"
    echo "11) Create Wazuh VM"
    echo "12) Create T-Pot VM"
    echo "13) Create PacketFence VM"
    echo
    echo "--------- OTHER ------------------------"
    echo
    echo "80) Create Image Server VM"
    echo "89) Change Proxmox repo"
    echo "99) Cleanup installation files"
    echo "666) Create MrNobody VM"
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

            install_openvswitch

            pause

            ;;


        3)

            configure_opnsense

            bash "$OPNSENSE" "$LAB"

            pause

            ;;


        4)

            configure_guacamole

            bash "$GUACVM02" "$LAB"

            pause

            ;;


        5)

            bash "$VULNSRV01" "$LAB"

            pause

            ;;


        6)

            bash "$VULNSRV02" "$LAB"

            pause

            ;;


        7)

            bash "$KALI01" "$LAB"

            pause

            ;;


        8)

            bash "$KALI02" "$LAB"

            pause

            ;;


        9)

            bash "$APPSRV01" "$LAB"

            pause

            ;;


        10)

            bash "$CLIENT01" "$LAB"

            pause

            ;;


        11)

            bash "$WAZUH" "$LAB"

            pause

            ;;


        12)

            bash "$TPOT" "$LAB"

            pause

            ;;


        13)

            bash "$PACKETFENCE" "$LAB"

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
        # MAIN CYBERLAB INSTALL
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

            bash "$MRNOBODY" "$LAB"

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