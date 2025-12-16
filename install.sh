#!/bin/bash
set -e

GUACVM="./GUACVM/GUACVM_installer.sh"

echo "Starting Guacamole VM creation..."
bash "$GUACVM"

echo "Guacamole VM creation script finished."
