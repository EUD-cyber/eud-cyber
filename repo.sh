#!/bin/bash
set -e

echo "=== Proxmox VE 9 repository setup ==="

# Hard-fail if not PVE 9
if ! pveversion | grep -q "pve-manager/9"; then
    echo "ERROR: This script is for Proxmox VE 9 only."
    exit 1
fi

DEBIAN_CODENAME="trixie"

echo "Detected Proxmox VE 9 (Debian $DEBIAN_CODENAME)"

ENTERPRISE_FILE="/etc/apt/sources.list.d/pve-enterprise.sources"

# Function: check if enterprise repo is enabled
is_enterprise_enabled() {
    [ -f "$ENTERPRISE_FILE" ] && grep -q "Enabled: 1" "$ENTERPRISE_FILE"
}

# =========================
# CHECK ENTERPRISE STATUS
# =========================
if is_enterprise_enabled; then
    echo "[INFO] Enterprise repository is ENABLED."

    read -r -p "Do you want to disable enterprise and use no-subscription repo? (y/N): " choice

    case "$choice" in
        y|Y|yes|YES)

            echo "[ACTION] Disabling enterprise repository..."
            sed -i 's/Enabled: 1/Enabled: 0/' "$ENTERPRISE_FILE"

            echo "[ACTION] Disabling Ceph enterprise repository..."
            sed -i 's/Enabled: 1/Enabled: 0/' /etc/apt/sources.list.d/ceph.sources 2>/dev/null || true

            echo "[ACTION] Adding no-subscription repository..."
            cat <<EOF > /etc/apt/sources.list.d/pve-no-subscription.list
deb http://download.proxmox.com/debian/pve $DEBIAN_CODENAME pve-no-subscription
EOF

            # Disable subscription popup
            POPUP_JS="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
            if [ -f "$POPUP_JS" ]; then
                echo "[ACTION] Disabling subscription popup..."
                sed -i.bak 's/data.status !== "Active"/false/' "$POPUP_JS"
                systemctl restart pveproxy
            fi

            echo "[ACTION] Updating package lists..."
            apt clean
            apt update

            echo "=== Done ==="
            echo "Enterprise disabled, no-subscription enabled."
            ;;

        *)
            echo "[INFO] Keeping enterprise repository."
            echo "[INFO] Skipping Proxmox repo changes."
            ;;
    esac

else
    echo "[INFO] Enterprise repository already DISABLED or not present."
    echo "[INFO] Skipping Proxmox repo setup."
fi
