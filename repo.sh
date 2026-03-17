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

PVE_ENTERPRISE_FILE="/etc/apt/sources.list.d/pve-enterprise.sources"
CEPH_ENTERPRISE_FILE="/etc/apt/sources.list.d/ceph.sources"
NO_SUB_FILE="/etc/apt/sources.list.d/pve-no-subscription.list"

is_pve_enterprise_enabled() {
    [ -f "$PVE_ENTERPRISE_FILE" ] && grep -qi '^URIs: .*enterprise\.proxmox\.com' "$PVE_ENTERPRISE_FILE"
}

is_ceph_enterprise_enabled() {
    [ -f "$CEPH_ENTERPRISE_FILE" ] && grep -qi '^URIs: .*enterprise\.proxmox\.com' "$CEPH_ENTERPRISE_FILE"
}

disable_pve_enterprise() {
    if [ -f "$PVE_ENTERPRISE_FILE" ]; then
        mv "$PVE_ENTERPRISE_FILE" "${PVE_ENTERPRISE_FILE}.disabled"
        echo "[OK] Disabled PVE enterprise repo"
    fi
}

disable_ceph_enterprise() {
    if [ -f "$CEPH_ENTERPRISE_FILE" ]; then
        mv "$CEPH_ENTERPRISE_FILE" "${CEPH_ENTERPRISE_FILE}.disabled"
        echo "[OK] Disabled Ceph enterprise repo"
    fi
}

ensure_no_subscription_repo() {
    echo "deb http://download.proxmox.com/debian/pve $DEBIAN_CODENAME pve-no-subscription" > "$NO_SUB_FILE"
    echo "[OK] Added no-subscription repo"
}

disable_subscription_popup() {
    POPUP_JS="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
    if [ -f "$POPUP_JS" ]; then
        echo "[INFO] Disabling subscription popup..."
        sed -i.bak 's/data.status !== "Active"/false/' "$POPUP_JS" || true
        systemctl restart pveproxy
        echo "[OK] Subscription popup patched"
    else
        echo "[WARN] Popup JS file not found"
    fi
}

if is_pve_enterprise_enabled; then
    echo "[INFO] Proxmox enterprise repo is ENABLED."
    read -r -p "Do you want to disable enterprise and use no-subscription repo? (y/N): " choice

    case "$choice" in
        y|Y|yes|YES)
            disable_pve_enterprise

            if is_ceph_enterprise_enabled; then
                disable_ceph_enterprise
            else
                echo "[INFO] Ceph enterprise repo not enabled or not present"
            fi

            ensure_no_subscription_repo
            disable_subscription_popup

            echo "[INFO] Updating package lists..."
            apt clean
            apt update

            echo "=== Done ==="
            echo "Enterprise repos disabled, no-subscription enabled."
            ;;
        *)
            echo "[INFO] Keeping enterprise repo enabled."
            echo "[INFO] Skipping Proxmox repo changes."
            ;;
    esac
else
    echo "[INFO] Proxmox enterprise repo already disabled or not present."
    echo "[INFO] Skipping Proxmox repo setup."
fi
