GUACVM_FILE="$(pwd)/GUACVM/GUACVM_installer.sh"

echo "Select network configuration:"
echo "1) DHCP"
echo "2) Static"
read -p "Enter choice [1-2]: " choice

if [ "$choice" = "1" ]; then

    IP_ADDR="ip=dhcp"
    DNS_SERVER=""

elif [ "$choice" = "2" ]; then

    read -p "Enter static IP (e.g., 192.168.1.100/24): " STATIC_IP
    read -p "Enter gateway (e.g., 192.168.1.1): " GATEWAY
    read -p "Enter DNS servers (space separated, e.g., 8.8.8.8 1.1.1.1): " DNS

    IP_ADDR="ip=${STATIC_IP},gw=${GATEWAY}"
    DNS_SERVER="$DNS"

else
    echo "Invalid choice. Exiting."
    exit 1
fi


# ------------------------------------------------
# Update values where the variable names already are
# ------------------------------------------------

# Replace lines if they exist
sed -i \
sed -i \
    -e "s|^IP_ADDR=.*|IP_ADDR=\"$IP_ADDR\"|" \
    -e "s|^DNS_SERVER=.*|DNS_SERVER=\"$DNS_SERVER\"|" \
    "$GUACVM_FILE"

echo "Updated $GUACVM_FILE:"
cat "$GUACVM_FILE"
