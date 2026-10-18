#!/bin/bash
set -e

# ============================================================
# CyberLab Deployment Menu
#
# BASIC:
#   - OPNsense
#   - Guacamole
#   - Kali01
#   - VulnSrv01
#
# OPTIONAL:
#   - VulnSrv02
#   - Kali02
#   - AppSrv01
#   - Client01
#   - Wazuh
#   - T-Pot
#   - PacketFence
#   - MrNobody
# ============================================================

LAB="1"

# ------------------------------------------------------------
# Script paths
# ------------------------------------------------------------

REPO="./repo.sh"
PREREQ="./pre_req.sh"

OPENVSWITCHPRE="./open-vswitch-multi-pre.sh"
OPENVSWITCH="./open-vswitch-multi.sh"
OPENVSWITCHLAST="./open-vswitch-multi-last.sh"

OPNSENSECONF="./OPNSENSE/generate_config_multi.sh"
OPNSENSE="./OPNSENSE/OPNSENSE_multi_installer.sh"

GUACVM_IP="./GUACVM/GUACVM_ip_multi.sh"
GUACVM="./GUACVM/GUACVM_multi_installer.sh"

GUACVM02_IP="./GUACVM02/GUACVM02_ip.sh"
GUACVM02="./GUACVM02/GUACVM02_installer.sh"

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


# ------------------------------------------------------------
# Check/install whiptail
# ------------------------------------------------------------

check_whiptail() {

    if ! command -v whiptail >/dev/null 2>&1; then

        echo "Installing whiptail..."
        apt-get update
        apt-get install -y whiptail

    fi
}


# ------------------------------------------------------------
# Prerequisites / network
# ------------------------------------------------------------

install_prerequisites() {

    echo
    echo "========================================"
    echo " Installing prerequisites"
    echo "========================================"

    echo
    echo "[1/2] Proxmox repository"
    bash "$REPO"

    echo
    echo "[2/2] Packages and snippets"
    bash "$PREREQ"
}


install_openvswitch() {

    echo
    echo "========================================"
    echo " Installing / configuring Open vSwitch"
    echo "========================================"

    bash "$OPENVSWITCHPRE"
    bash "$OPENVSWITCH" "$LAB"
    bash "$OPENVSWITCHLAST"
}


# ------------------------------------------------------------
# BASIC INSTALLATION
# ------------------------------------------------------------

install_basic() {

    echo
    echo "========================================"
    echo "       BASIC CYBERLAB INSTALLATION"
    echo "========================================"
    echo
    echo "Lab: $LAB"
    echo
    echo "Basic components:"
    echo "  - OPNsense"
    echo "  - Guacamole"
    echo "  - Kali01"
    echo "  - VulnSrv01"
    echo
    echo "========================================"


    # --------------------------------------------------------
    # Base Proxmox configuration
    # --------------------------------------------------------

    install_prerequisites

    install_openvswitch


    # --------------------------------------------------------
    # OPNsense
    #
    # Keep configuration and installation together.
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " OPNsense"
    echo "========================================"

    echo
    echo "[OPNsense] Generating configuration..."
    bash "$OPNSENSECONF" "$LAB"

    echo
    echo "[OPNsense] Creating VM..."
    bash "$OPNSENSE" "$LAB"


    # --------------------------------------------------------
    # Guacamole
    #
    # Keep IP configuration and installation together.
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Guacamole"
    echo "========================================"

    echo
    echo "[Guacamole] Configuring IP settings..."
    bash "$GUACVM02_IP" "$LAB"

    echo
    echo "[Guacamole] Creating VM..."
    bash "$GUACVM02" "$LAB"


    # --------------------------------------------------------
    # Kali01
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " Kali01"
    echo "========================================"

    bash "$KALI01" "$LAB"


    # --------------------------------------------------------
    # VulnSrv01
    # --------------------------------------------------------

    echo
    echo "========================================"
    echo " VulnSrv01"
    echo "========================================"

    bash "$VULNSRV01" "$LAB"


    echo
    echo "========================================"
    echo " BASIC installation completed"
    echo "========================================"
}


# ------------------------------------------------------------
# Optional component selector
# ------------------------------------------------------------

select_optional_components() {

    check_whiptail

    OPTIONS=$(whiptail \
        --title "CyberLab Optional Components" \
        --checklist \
"Basic is always installed:

  OPNsense
  Guacamole
  Kali01
  VulnSrv01

Select additional systems.

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

    EXITSTATUS=$?

    if [ "$EXITSTATUS" -ne 0 ]; then
        echo
        echo "Installation cancelled."
        exit 1
    fi
}


# ------------------------------------------------------------
# Install optional components
# ------------------------------------------------------------

install_optional_components() {

    echo
    echo "========================================"
    echo " Installing optional components"
    echo "========================================"

    if [ -z "$OPTIONS" ]; then
        echo
        echo "No optional components selected."
        return
    fi


    for COMPONENT in $OPTIONS; do

        COMPONENT=$(echo "$COMPONENT" | tr -d '"')

        case "$COMPONENT" in

            VULNSRV02)

                echo
                echo "========================================"
                echo " VulnSrv02"
                echo "========================================"

                bash "$VULNSRV02" "$LAB"
                ;;


            KALI02)

                echo
                echo "========================================"
                echo " Kali02"
                echo "========================================"

                bash "$KALI02" "$LAB"
                ;;


            APPSRV01)

                echo
                echo "========================================"
                echo " AppSrv01"
                echo "========================================"

                bash "$APPSRV01" "$LAB"
                ;;


            CLIENT01)

                echo
                echo "========================================"
                echo " Client01"
                echo "========================================"

                bash "$CLIENT01" "$LAB"
                ;;


            WAZUH)

                echo
                echo "========================================"
                echo " Wazuh"
                echo "========================================"

                bash "$WAZUH" "$LAB"
                ;;


            TPOT)

                echo
                echo "========================================"
                echo " T-Pot"
                echo "========================================"

                bash "$TPOT" "$LAB"
                ;;


            PACKETFENCE)

                echo
                echo "========================================"
                echo " PacketFence"
                echo "========================================"

                bash "$PACKETFENCE" "$LAB"
                ;;


            MRNOBODY)

                echo
                echo "========================================"
                echo " MrNobody"
                echo "========================================"

                bash "$MRNOBODY" "$LAB"
                ;;

        esac

    done
}


# ------------------------------------------------------------
# Basic + optional installation
# ------------------------------------------------------------

custom_install() {

    clear

    check_whiptail

    # Select optional systems BEFORE starting deployment
    select_optional_components

    clear

    echo "========================================"
    echo "       CyberLab Deployment"
    echo "========================================"
    echo
    echo "Lab number: $LAB"
    echo
    echo "BASIC:"
    echo "  OPNsense"
    echo "  Guacamole"
    echo "  Kali01"
    echo "  VulnSrv01"
    echo

    if [ -n "$OPTIONS" ]; then

        echo "OPTIONAL:"

        for COMPONENT in $OPTIONS; do
            echo "  - $(echo "$COMPONENT" | tr -d '"')"
        done

    else

        echo "OPTIONAL:"
        echo "  None"

    fi

    echo
    echo "========================================"

    read -rp "Start installation? [y/N]: " CONFIRM

    case "$CONFIRM" in
        y|Y|yes|YES)
            ;;
        *)
            echo "Installation cancelled."
            exit 0
            ;;
    esac


    install_basic

    install_optional_components


    echo
    echo "========================================"
    echo "     CYBERLAB DEPLOYMENT COMPLETE"
    echo "========================================"
}


# ============================================================
# Main menu
# ============================================================

while true; do

    clear

    echo "========================================"
    echo "       Proxmox Deployment Menu"
    echo "========================================"
    echo
    echo "Lab number: $LAB"
    echo
    echo "----- Complete installations -----------"
    echo
    echo "90) Basic + select optional components"
    echo
    echo "----- Basic components -----------------"
    echo
    echo "1)  Check packages & snippets"
    echo "2)  Install & configure Open vSwitch"
    echo "3)  Create OPNsense VM"
    echo "4)  Create Guacamole VM"
    echo "5)  Create Vuln-server01 VM"
    echo "7)  Create KALI01 VM"
    echo
    echo "----- Optional components --------------"
    echo
    echo "6)  Create Vuln-server02 VM"
    echo "8)  Create KALI02 VM"
    echo "9)  Create APPSRV01 VM"
    echo "10) Create Client01 VM"
    echo "11) Create WAZUH VM"
    echo "12) Create TPOT01 VM"
    echo "13) Create PacketFence VM"
    echo
    echo "----- Other ----------------------------"
    echo
    echo "80) Create Image Server VM"
    echo "89) Change Proxmox repo to no-enterprise"
    echo "99) Cleanup installation"
    echo "666) Create MrNobody VM"
    echo
    echo "0) Exit"
    echo
    echo "========================================"

    read -rp "Enter your choice: " CHOICE


    case "$CHOICE" in

        # ----------------------------------------------------
        # Individual installation
        # ----------------------------------------------------

        1)
            bash "$PREREQ"
            pause
            ;;


        2)
            install_openvswitch
            pause
            ;;


        3)
            echo "Generating OPNsense configuration..."
            bash "$OPNSENSECONF" "$LAB"

            echo "Creating OPNsense VM..."
            bash "$OPNSENSE" "$LAB"

            pause
            ;;


        4)
            echo "Configuring Guacamole IP settings..."
            bash "$GUACVM02_IP" "$LAB"

            echo "Creating Guacamole VM..."
            bash "$GUACVM02" "$LAB"

            pause
            ;;


        5)
            echo "Creating VulnSrv01..."
            bash "$VULNSRV01" "$LAB"
            pause
            ;;


        6)
            echo "Creating VulnSrv02..."
            bash "$VULNSRV02" "$LAB"
            pause
            ;;


        7)
            echo "Creating Kali01..."
            bash "$KALI01" "$LAB"
            pause
            ;;


        8)
            echo "Creating Kali02..."
            bash "$KALI02" "$LAB"
            pause
            ;;


        9)
            echo "Creating AppSrv01..."
            bash "$APPSRV01" "$LAB"
            pause
            ;;


        10)
            echo "Creating Client01..."
            bash "$CLIENT01" "$LAB"
            pause
            ;;


        11)
            echo "Creating Wazuh..."
            bash "$WAZUH" "$LAB"
            pause
            ;;


        12)
            echo "Creating T-Pot..."
            bash "$TPOT" "$LAB"
            pause
            ;;


        13)
            echo "Creating PacketFence..."
            bash "$PACKETFENCE" "$LAB"
            pause
            ;;


        # ----------------------------------------------------
        # Image server
        # ----------------------------------------------------

        80)
            echo "Creating Image Server..."
            bash "$IMAGESRV" "99"
            pause
            ;;


        # ----------------------------------------------------
        # Repository
        # ----------------------------------------------------

        89)
            echo "Changing Proxmox repository..."
            bash "$REPO"
            pause
            ;;


        # ----------------------------------------------------
        # NEW INSTALLATION
        # ----------------------------------------------------

        90)
            custom_install
            pause
            ;;


        # ----------------------------------------------------
        # Cleanup
        # ----------------------------------------------------

        99)

            echo
            echo "WARNING!"
            echo
            echo "This will remove:"
            echo "  ./eud-cyber"
            echo "  /var/lib/vz/snippets/*"
            echo "  /var/lib/vz/template/iso/*"
            echo

            read -rp "Are you sure? Type YES: " CONFIRM

            if [ "$CONFIRM" = "YES" ]; then

                rm -rf ./eud-cyber
                rm -rf /var/lib/vz/snippets/*
                rm -rf /var/lib/vz/template/iso/*

                echo "Cleanup completed."

            else

                echo "Cleanup cancelled."

            fi

            pause
            ;;


        # ----------------------------------------------------
        # MrNobody
        # ----------------------------------------------------

        666)
            echo "Creating MrNobody..."
            bash "$MRNOBODY" "$LAB"
            pause
            ;;


        # ----------------------------------------------------
        # Exit
        # ----------------------------------------------------

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