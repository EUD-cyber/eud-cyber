  A|a)
    read -rp "How many labs to prepare (1–16): " LABCOUNT

    if ! [[ "$LABCOUNT" =~ ^[0-9]+$ ]] || [ "$LABCOUNT" -lt 1 ] || [ "$LABCOUNT" -gt 16 ]; then
      echo "❌ Invalid number. Must be between 1 and 16."
      exit 1
    fi

    echo "===== Base setup (run once) ====="

    echo "Change proxmox repo to no-enterprise"
    bash "$REPO" || exit 1

    echo "Checking packages and snippets..."
    bash "$PREREQ" || exit 1

    echo "Starting Open vSwitch installation and configuration"
    bash "$OPENVSWITCH" || exit 1

    echo "===== Preparing $LABCOUNT labs ====="

    for i in $(seq 1 "$LABCOUNT"); do
      echo
      echo "----- Lab $i -----"

      echo "Generating OPNsense config for lab $i"
      bash "$OPNSENSECONF" || exit 1

      echo "Configuring Guacamole IP for lab $i"
      bash "$GUACVM_IP" || exit 1
    done

    echo
    echo "✅ $LABCOUNT labs prepared successfully"
    ;;

