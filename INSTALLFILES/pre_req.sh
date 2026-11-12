#!/bin/bash
set -e

#check if snippets folder exits if not create it
STORAGE_CFG="/etc/pve/storage.cfg"
STORAGE_NAME="local"
STORAGE_PATH="/var/lib/vz"
SNIPPETS_DIR="${STORAGE_PATH}/snippets"

echo "Checking Proxmox snippets configuration..."

# 1. Check storage exists
if ! grep -q "^dir: ${STORAGE_NAME}" "$STORAGE_CFG"; then
  echo "ERROR: Storage '${STORAGE_NAME}' not found in storage.cfg"
  exit 1
fi

# 2. Check if snippets is already enabled
if grep -A5 "^dir: ${STORAGE_NAME}" "$STORAGE_CFG" | grep -q "snippets"; then
  echo "✔ Snippets already enabled in storage.cfg"
else
  echo "➕ Enabling snippets in storage.cfg..."

  # Append snippets to content line safely
  sed -i "/^dir: ${STORAGE_NAME}/,/^$/{
    s/content \(.*\)/content \1,snippets/
  }" "$STORAGE_CFG"

  echo "✔ Snippets enabled"
fi

# 3. Ensure snippets directory exists
if [ ! -d "$SNIPPETS_DIR" ]; then
  echo "➕ Creating snippets directory: $SNIPPETS_DIR"
  mkdir -p "$SNIPPETS_DIR"
else
  echo "✔ Snippets directory already exists"
fi

# 4. Permissions
chmod 755 "$SNIPPETS_DIR"

echo "✔ Proxmox snippets setup complete"

#check if packages is installed is not install them
PACKAGES=(wget bzip2 openvswitch-switch ifupdown2 ipcalc libguestfs-tools xz-utils unzip zip expect xorriso genisoimage rsync ansible-core tmux)

for pkg in "${PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "[+] Installing $pkg..."
    apt-get update -qq
    apt-get install -y "$pkg"
  else
    echo "[✓] $pkg already installed"
  fi
done

