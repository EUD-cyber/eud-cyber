

  
  
  A|a)
    read -rp "How many labs to prepare (1–16): " LABCOUNT

    if ! [[ "$LABCOUNT" =~ ^[0-9]+$ ]] || [ "$LABCOUNT" -lt 1 ] || [ "$LABCOUNT" -gt 16 ]; then
      echo "❌ Invalid number. Must be between 1 and 16."
      exit 1
    fi

    echo
    echo "===== Base setup (run once) ====="

    echo "Change proxmox repo to no-enterprise"
    bash "$REPO" || exit 1

    echo "Checking packages and snippets..."
    bash "$PREREQ" || exit 1

    echo
    echo "===== Open vSwitch pre-setup ====="
    bash "./openvswitch-pre.sh" || exit 1

    echo
    echo "===== Preparing $LABCOUNT labs ====="

    for i in $(seq 1 "$LABCOUNT"); do
      echo
      echo "----- Lab $i -----"

      echo "Creating Open vSwitch bridges for lab $i"
      bash "./openvswitch-lab.sh" "$i" || exit 1

      echo "Generating OPNsense config for lab $i"
      bash "$OPNSENSECONF" || exit 1

      echo "Configuring Guacamole IP for lab $i"
      bash "$GUACVM_IP" || exit 1
    done

    echo
    echo "===== Open vSwitch post-setup ====="
    bash "./openvswitch-post.sh" || exit 1

    echo
    echo "✅ $LABCOUNT labs prepared successfully"
    ;;
