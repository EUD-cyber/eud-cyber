#!/bin/bash
set -e


GUACVM="./GUACVM/GUACVM_installer.sh"
OPENVSWITCH="./open-vswitch.sh"
VULNSRV01="./VULNSRV01/VULNSRV01_installer.sh"
OPNSENSE="./OPENSENSE/OPNSENSE_installer.sh"
PREREQ="./pre_req.sh"

echo "check package and snippet if  exits if not creating it"
bash "$PREREQ"
echo "Starting Open-vswitch installation and configuration"
bash "$OPENVSWITCH"
echo "Starting Opnsense VM creation..."
bash "$OPNSENSE"
echo "Starting Guacamole VM creation..."
bash "$GUACVM"
echo "Starting Vuln-server01 VM creation..."
bash "$VULNSRV01"




