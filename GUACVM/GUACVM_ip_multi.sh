GUACVM_FILE="$(pwd)/GUACVM/GUACVM_installer.sh"

LAB="$1"
if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  exit 1
fi
STATE_DIR="$(pwd)/GUACVM/STATE"
STATE_FILE="${STATE_DIR}/lab${LAB}.env"

mkdir -p "$STATE_DIR"


# Function to validate IPv4 address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for octet in ${ip//./ }; do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

while true; do
    echo "GUACVM ip config"
    echo "Select network configuration:"
    echo "1) DHCP"
    echo "2) Static"
    echo "3) Exit"
    read -p "Enter choice [1-3]: " choice

    case $choice in
        1)
            IP_ADDR="ip=dhcp"
            DNS_SERVER=""
            break
            ;;

        2)
            # ---- Static IP (with CIDR) ----
            while true; do
                read -p "Enter static IP (e.g., 192.168.1.100/24): " STATIC_IP
                IP_ONLY="${STATIC_IP%%/*}"
                CIDR="${STATIC_IP##*/}"

                if ! validate_ip "$IP_ONLY"; then
                    echo "❌ Invalid IP address."
                    continue
                fi

                if [[ ! "$CIDR" =~ ^([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
                    echo "❌ Invalid CIDR (must be 0-32)."
                    continue
                fi

                break
            done

            # ---- Gateway ----
            while true; do
                read -p "Enter gateway (e.g., 192.168.1.1): " GATEWAY
                if validate_ip "$GATEWAY"; then
                    break
                else
                    echo "❌ Invalid gateway IP."
                fi
            done

            # ---- DNS Servers ----
            while true; do
                read -p "Enter DNS server (e.g., 8.8.8.8): " DNS
                valid_dns=true

                for dns_ip in $DNS; do
                    if ! validate_ip "$dns_ip"; then
                        echo "❌ Invalid DNS server: $dns_ip"
                        valid_dns=false
                        break
                    fi
                done

                $valid_dns && break
            done

            IP_ADDR="ip=${STATIC_IP},gw=${GATEWAY}"
            DNS_SERVER="$DNS"
            break
            ;;

        3)
            echo "Exiting script."
            exit 0
            ;;

        *)
            echo "❌ Invalid choice. Please select 1, 2, or 3."
            ;;
    esac
done


# ------------------------------------------------
# Update values where the variable names already are
# ------------------------------------------------

cat > "$STATE_FILE" <<EOF
GUAC_IP_ADDR="$IP_ADDR"
GUAC_DNS_SERVER="$DNS_SERVER"
EOF

echo "✔ Stored Guacamole network config for lab $LAB"
echo "  → $STATE_FILE"

echo
echo "Summary for lab $LAB:"
echo "  IP  : $IP_ADDR"
echo "  DNS : ${DNS_SERVER:-<none>}"

