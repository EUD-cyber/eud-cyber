#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
# Cyberlab main installer
#
# Lets the administrator choose between:
#   1. Internet image sources
#   2. CyberRepo / ImageSrv discovered through manifest.json
#
# Ubuntu, Kali, Wazuh and OPNsense URLs are exported as:
#   LINUX_IMG
#   KALI_IMG
#   WAZUH_IMG
#   OPNSENSE_IMG_URL
#
# OPNSENSE_VERSION is exported as well. If an OPNsense image is selected from
# CyberRepo, the version is detected automatically from the filename.
###############################################################################

SCRIPT_DIR="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
  pwd
)"

cd "$SCRIPT_DIR"

###############################################################################
# Default image sources
###############################################################################

INTERNET_LINUX_IMG="https://cloud-images.ubuntu.com/noble/20260725/noble-server-cloudimg-amd64.img"
INTERNET_WAZUH_IMG="https://packages.wazuh.com/4.x/vm/wazuh-4.14.1.ova"
INTERNET_KALI_IMG="https://kali.download/cloud-images/kali-2025.4/kali-linux-2025.4-cloud-genericcloud-amd64.tar.xz"

DEFAULT_IMAGE_SERVER="http://10.134.71.139"

OPNSENSE_VERSION="26.1.2"
INTERNET_OPNSENSE_IMG="https://pkg.opnsense.org/releases/${OPNSENSE_VERSION}/OPNsense-${OPNSENSE_VERSION}-nano-amd64.img.bz2"

###############################################################################
# Deployment scripts
###############################################################################

FULL_INSTALL="${SCRIPT_DIR}/full_install.sh"
MINI_INSTALL="${SCRIPT_DIR}/mini_install.sh"
MULTI_INSTALL="${SCRIPT_DIR}/multi_install.sh"
MULTI_INSTALL_MINI="${SCRIPT_DIR}/multi_mini_install.sh"
NEW_FULL_INSTALL="${SCRIPT_DIR}/new_full_install.sh"

###############################################################################
# Helper functions
###############################################################################

log() {
  printf '[+] %s\n' "$*"
}

warning() {
  printf '[WARNING] %s\n' "$*" >&2
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

url_is_reachable() {
  local url="$1"

  wget \
    --spider \
    --quiet \
    --timeout=15 \
    --tries=2 \
    "$url"
}
format_bytes() {
  local bytes="${1:-0}"

  awk -v bytes="$bytes" '
    BEGIN {
      split("B KiB MiB GiB TiB", units, " ")
      unit = 1

      while (bytes >= 1024 && unit < 5) {
        bytes /= 1024
        unit++
      }

      printf "%.2f %s", bytes, units[unit]
    }
  '
}

require_file() {
  local file="$1"

  [[ -s "$file" ]] ||
    die "Required installer is missing or empty: ${file}"
}

validate_url_or_die() {
  local description="$1"
  local url="$2"

  log "Testing ${description}:"
  printf '    %s\n' "$url"

  url_is_reachable "$url" ||
    die "${description} is not reachable: ${url}"
}

download_manifest() {
  local server_url="$1"
  local destination="$2"

  log "Downloading CyberRepo manifest..."

  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --connect-timeout 10 \
    --max-time 60 \
    --output "$destination" \
    "${server_url}/manifest.json"

  python3 - "$destination" <<'PY'
import json
import sys

manifest_path = sys.argv[1]

with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)

if not isinstance(manifest, dict):
    raise SystemExit("Manifest root is not an object.")

if not isinstance(manifest.get("files"), list):
    raise SystemExit("Manifest does not contain a valid files list.")
PY
}

show_all_repo_images() {
  local manifest_file="$1"

  echo
  echo "======================================================"
  echo " Images available on CyberRepo"
  echo "======================================================"

  python3 - "$manifest_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)

files = [
    item for item in manifest.get("files", [])
    if str(item.get("path", "")).startswith("images/")
]

if not files:
    print("No VM images were found in the manifest.")
    raise SystemExit(0)

def human_size(size):
    value = float(size or 0)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024

for item in sorted(files, key=lambda value: str(value.get("path", ""))):
    path = str(item.get("path", ""))
    size = int(item.get("size", 0) or 0)

    print(f"- {path}")
    print(f"  Size: {human_size(size)}")
PY
}

select_manifest_image() {
  local image_role="$1"
  local search_regex="$2"
  local internet_url="$3"
  local manifest_file="$4"

  local -a paths=()
  local -a urls=()
  local -a sizes=()
  local -a hashes=()

  local path
  local url
  local size
  local sha256

  while IFS=$'\t' read -r path url size sha256; do
    [[ -n "$path" ]] || continue

    paths+=("$path")
    urls+=("$url")
    sizes+=("$size")
    hashes+=("$sha256")
  done < <(
    python3 - "$manifest_file" "$search_regex" <<'PY'
import json
import re
import sys

manifest_path = sys.argv[1]
pattern = re.compile(sys.argv[2], re.IGNORECASE)

with open(manifest_path, encoding="utf-8") as source:
    manifest = json.load(source)

for item in manifest.get("files", []):
    path = str(item.get("path", ""))

    if not pattern.search(path):
        continue

    url = str(item.get("url", ""))
    size = int(item.get("size", 0) or 0)
    sha256 = str(item.get("sha256", ""))

    print(f"{path}\t{url}\t{size}\t{sha256}")
PY
  )

  echo
  echo "------------------------------------------------------"
  echo "${image_role} images"
  echo "------------------------------------------------------"

  if [[ ${#paths[@]} -eq 0 ]]; then
    warning "No ${image_role} image was found on CyberRepo."

    read -r -p \
      "Use the internet image for ${image_role}? [Y/n]: " \
      use_internet

    use_internet="${use_internet:-y}"

    if [[ "$use_internet" =~ ^[Yy]$ ]]; then
      SELECTED_IMAGE_URL="$internet_url"
      SELECTED_IMAGE_SOURCE="Internet"
      SELECTED_IMAGE_PATH=""
      return 0
    fi

    die "${image_role} image is required."
  fi

  local index

  for index in "${!paths[@]}"; do
    printf '%d) %s\n' \
      "$((index + 1))" \
      "${paths[$index]}"

    printf '   Size: %s\n' \
      "$(format_bytes "${sizes[$index]}")"

    printf '   URL:  %s\n' \
      "${urls[$index]}"

    if [[ -n "${hashes[$index]}" ]]; then
      printf '   SHA256: %.16s...\n' \
        "${hashes[$index]}"
    fi

    echo
  done

  local internet_option=$(( ${#paths[@]} + 1 ))

  echo "${internet_option}) Use internet image"
  echo "0) Stop installation"
  echo

  local selection

  while true; do
    read -r -p \
      "Select ${image_role} image [1]: " \
      selection

    selection="${selection:-1}"

    if [[ "$selection" == "0" ]]; then
      die "Installation cancelled."
    fi

    if [[ "$selection" == "$internet_option" ]]; then
      SELECTED_IMAGE_URL="$internet_url"
      SELECTED_IMAGE_SOURCE="Internet"
      SELECTED_IMAGE_PATH=""
      return 0
    fi

    if [[ "$selection" =~ ^[0-9]+$ ]] &&
       (( selection >= 1 && selection <= ${#paths[@]} )); then

      SELECTED_IMAGE_URL="${urls[$((selection - 1))]}"
      SELECTED_IMAGE_SOURCE="CyberRepo"
      SELECTED_IMAGE_PATH="${paths[$((selection - 1))]}"
      return 0
    fi

    echo "Invalid selection. Try again."
  done
}

select_storage() {
  local prompt="$1"
  shift

  local -a options=("$@")
  local selected=""

  echo
  echo "$prompt"

  PS3="Select storage: "

  select selected in "${options[@]}"; do
    if [[ -n "$selected" ]]; then
      printf '%s' "$selected"
      return 0
    fi

    echo "Invalid selection. Try again."
  done
}

select_bridge() {
  local -a options=("$@")
  local selected=""

  echo
  echo "Available network bridges:"

  PS3="Select network bridge: "

  select selected in "${options[@]}"; do
    if [[ -n "$selected" ]]; then
      printf '%s' "$selected"
      return 0
    fi

    echo "Invalid selection. Try again."
  done
}

infer_opnsense_version() {
  local image_url="$1"
  local filename
  local detected_version=""

  filename="$(basename "${image_url%%\?*}")"

  if [[ "$filename" =~ ^OPNsense-([0-9]+\.[0-9]+(\.[0-9]+)?)-nano-amd64\.img\.bz2$ ]]; then
    detected_version="${BASH_REMATCH[1]}"
  fi

  if [[ -n "$detected_version" ]]; then
    OPNSENSE_VERSION="$detected_version"
    log "Detected OPNsense version: ${OPNSENSE_VERSION}"
  else
    warning "Could not detect OPNsense version from ${filename}."
    warning "Keeping configured version: ${OPNSENSE_VERSION}"
  fi
}

###############################################################################
# Validate host
###############################################################################

[[ "$EUID" -eq 0 ]] ||
  die "Run this installer as root."

command_exists pvesm ||
  die "pvesm was not found. Run this on a Proxmox host."

command_exists curl ||
  die "curl is required."

command_exists python3 ||
  die "python3 is required."

command_exists awk ||
  die "awk is required."

###############################################################################
# Select image source
###############################################################################

clear

echo "======================================================"
echo " Cyberlab image source"
echo "======================================================"
echo
echo "1) Use images from the internet"
echo "2) Discover and select images from CyberRepo / ImageSrv"
echo "0) Exit"
echo

read -r -p "Select image source [1-2]: " IMAGE_SOURCE_CHOICE

IMAGE_SERVER_URL=""
MANIFEST_FILE=""

case "$IMAGE_SOURCE_CHOICE" in
  1)
    IMAGE_SOURCE="Internet"

    validate_url_or_die \
      "Ubuntu image" \
      "$INTERNET_LINUX_IMG"

    validate_url_or_die \
      "Kali image" \
      "$INTERNET_KALI_IMG"

    validate_url_or_die \
      "Wazuh image" \
      "$INTERNET_WAZUH_IMG"

    LINUX_IMG="$INTERNET_LINUX_IMG"
    KALI_IMG="$INTERNET_KALI_IMG"
    WAZUH_IMG="$INTERNET_WAZUH_IMG"
    OPNSENSE_IMG_URL="$INTERNET_OPNSENSE_IMG"

    LINUX_IMAGE_SOURCE="Internet"
    KALI_IMAGE_SOURCE="Internet"
    WAZUH_IMAGE_SOURCE="Internet"
    OPNSENSE_IMAGE_SOURCE="Internet"
    ;;

  2)
    IMAGE_SOURCE="CyberRepo"

    echo

    read -r -p \
      "CyberRepo URL [${DEFAULT_IMAGE_SERVER}]: " \
      IMAGE_SERVER_URL

    IMAGE_SERVER_URL="${IMAGE_SERVER_URL:-$DEFAULT_IMAGE_SERVER}"
    IMAGE_SERVER_URL="${IMAGE_SERVER_URL%/}"

    log "Testing CyberRepo health endpoint..."

    url_is_reachable "${IMAGE_SERVER_URL}/health" ||
      die "CyberRepo is unavailable: ${IMAGE_SERVER_URL}/health"

    log "CyberRepo is online."

    MANIFEST_FILE="$(mktemp)"
    trap 'rm -f "${MANIFEST_FILE:-}"' EXIT

    download_manifest "$IMAGE_SERVER_URL" "$MANIFEST_FILE"
    show_all_repo_images "$MANIFEST_FILE"

    select_manifest_image \
      "Ubuntu" \
      '^images/ubuntu/.*\.(img|qcow2|raw|zst|xz|gz)$' \
      "$INTERNET_LINUX_IMG" \
      "$MANIFEST_FILE"

    LINUX_IMG="$SELECTED_IMAGE_URL"
    LINUX_IMAGE_SOURCE="$SELECTED_IMAGE_SOURCE"

    select_manifest_image \
      "Kali" \
      '^images/kali/.*\.(img|qcow2|raw|tar\.xz|xz|zst|gz)$' \
      "$INTERNET_KALI_IMG" \
      "$MANIFEST_FILE"

    KALI_IMG="$SELECTED_IMAGE_URL"
    KALI_IMAGE_SOURCE="$SELECTED_IMAGE_SOURCE"

    select_manifest_image \
      "Wazuh" \
      '^images/wazuh/.*\.(ova|ovf|qcow2|img|raw|zst|xz|gz)$' \
      "$INTERNET_WAZUH_IMG" \
      "$MANIFEST_FILE"

    WAZUH_IMG="$SELECTED_IMAGE_URL"
    WAZUH_IMAGE_SOURCE="$SELECTED_IMAGE_SOURCE"

    select_manifest_image       "OPNsense"       '^images/opnsense/.*OPNsense-[0-9]+\.[0-9]+(\.[0-9]+)?-nano-amd64\.img\.bz2$'       "$INTERNET_OPNSENSE_IMG"       "$MANIFEST_FILE"

    OPNSENSE_IMG_URL="$SELECTED_IMAGE_URL"
    OPNSENSE_IMAGE_SOURCE="$SELECTED_IMAGE_SOURCE"

    infer_opnsense_version "$OPNSENSE_IMG_URL"
    ;;

  0)
    echo "Exiting..."
    exit 0
    ;;

  *)
    die "Invalid image source selection."
    ;;
esac

export IMAGE_SOURCE
export IMAGE_SERVER_URL
export LINUX_IMG
export KALI_IMG
export WAZUH_IMG
export OPNSENSE_IMG_URL
export OPNSENSE_VERSION

###############################################################################
# Confirm selected images
###############################################################################

echo
echo "======================================================"
echo " Selected images"
echo "======================================================"
echo
echo "Ubuntu (${LINUX_IMAGE_SOURCE}):"
echo "  ${LINUX_IMG}"
echo
echo "Kali (${KALI_IMAGE_SOURCE}):"
echo "  ${KALI_IMG}"
echo
echo "Wazuh (${WAZUH_IMAGE_SOURCE}):"
echo "  ${WAZUH_IMG}"
echo
echo "OPNsense (${OPNSENSE_IMAGE_SOURCE}):"
echo "  ${OPNSENSE_IMG_URL}"
echo "  Version: ${OPNSENSE_VERSION}"
echo

read -r -p "Use these images? [Y/n]: " CONFIRM_IMAGES
CONFIRM_IMAGES="${CONFIRM_IMAGES:-y}"

if [[ ! "$CONFIRM_IMAGES" =~ ^[Yy]$ ]]; then
  echo "Installation cancelled."
  exit 0
fi

###############################################################################
# Detect storage
###############################################################################

echo
echo "Detecting available Proxmox storage..."

mapfile -t ISO_LIST < <(
  pvesm status --content iso |
  awk 'NR > 1 {print $1}' |
  sort -u
)

mapfile -t DISK_LIST < <(
  pvesm status --content images |
  awk 'NR > 1 {print $1}' |
  sort -u
)

[[ ${#ISO_LIST[@]} -gt 0 ]] ||
  die "No ISO-capable storage was found."

[[ ${#DISK_LIST[@]} -gt 0 ]] ||
  die "No VM disk-capable storage was found."

echo
echo "Available ISO storages:"

PS3="Select ISO storage: "

select ISO_STORAGE in "${ISO_LIST[@]}"; do
  if [[ -n "$ISO_STORAGE" ]]; then
    break
  fi

  echo "Invalid selection. Try again."
done

echo
echo "Available VM disk storages:"

PS3="Select VM disk storage: "

select DISK_STORAGE in "${DISK_LIST[@]}"; do
  if [[ -n "$DISK_STORAGE" ]]; then
    break
  fi

  echo "Invalid selection. Try again."
done

export LOCAL="$ISO_STORAGE"
export LVM="$DISK_STORAGE"

echo
echo "ISO storage selected: ${LOCAL}"
echo "Disk storage selected: ${LVM}"

###############################################################################
# Detect bridges
###############################################################################

echo
echo "Detecting available Linux and OVS bridges..."

BRIDGE_LIST=()

if command_exists ip; then
  while IFS= read -r bridge; do
    [[ -n "$bridge" ]] || continue

    if [[ "$bridge" == lab* || "$bridge" == prox* ]]; then
      continue
    fi

    BRIDGE_LIST+=("$bridge")
  done < <(
    ip -o link show type bridge |
    awk -F': ' '{print $2}' |
    cut -d'@' -f1
  )
fi

if command_exists ovs-vsctl; then
  while IFS= read -r bridge; do
    [[ -n "$bridge" ]] || continue

    if [[ "$bridge" == lab* || "$bridge" == prox* ]]; then
      continue
    fi

    BRIDGE_LIST+=("$bridge")
  done < <(
    ovs-vsctl list-br
  )
fi

[[ ${#BRIDGE_LIST[@]} -gt 0 ]] ||
  die "No usable network bridges were found."

mapfile -t BRIDGE_LIST < <(
  printf '%s\n' "${BRIDGE_LIST[@]}" |
  sort -u
)

echo
echo "Available network bridges:"

PS3="Select network bridge: "

select SELECTED_BRIDGE in "${BRIDGE_LIST[@]}"; do
  if [[ -n "$SELECTED_BRIDGE" ]]; then
    break
  fi

  echo "Invalid selection. Try again."
done

export BRIDGE="$SELECTED_BRIDGE"

echo
echo "Bridge selected: ${BRIDGE}"

###############################################################################
# Deployment menu
###############################################################################

clear

echo "======================================================"
echo " Proxmox Deployment"
echo "======================================================"
echo
echo "Image source: ${IMAGE_SOURCE}"
echo "Ubuntu:       ${LINUX_IMAGE_SOURCE}"
echo "Kali:         ${KALI_IMAGE_SOURCE}"
echo "Wazuh:        ${WAZUH_IMAGE_SOURCE}"
echo "OPNsense:     ${OPNSENSE_IMAGE_SOURCE}"
echo
echo "ISO storage:  ${LOCAL}"
echo "Disk storage: ${LVM}"
echo "Bridge:       ${BRIDGE}"
echo
echo "1) Standalone Proxmox (Full Lab)"
echo "2) Standalone Proxmox (Mini Lab low spec)"
echo "3) Multilabs full spec on same Proxmox"
echo "4) Multilabs mini spec on same Proxmox"
echo "5) New test install"
echo "0) Exit"
echo
echo "======================================================"

read -r -p "Select deployment type: " choice

case "$choice" in
  1)
    require_file "$FULL_INSTALL"
    echo "▶ Standalone Proxmox (Full Lab)"
    bash "$FULL_INSTALL"
    ;;

  2)
    require_file "$MINI_INSTALL"
    echo "▶ Standalone Proxmox (Mini Lab low spec)"
    bash "$MINI_INSTALL"
    ;;

  3)
    require_file "$MULTI_INSTALL"
    echo "▶ Multilabs full spec on same Proxmox"
    bash "$MULTI_INSTALL"
    ;;

  4)
    require_file "$MULTI_INSTALL_MINI"
    echo "▶ Multilabs mini spec on same Proxmox"
    bash "$MULTI_INSTALL_MINI"
    ;;

  5)
    require_file "$NEW_FULL_INSTALL"
    echo "▶ New test install"
    bash "$NEW_FULL_INSTALL"
    ;;

  0)
    echo "Exiting..."
    exit 0
    ;;

  *)
    die "Invalid deployment option."
    ;;
esac
