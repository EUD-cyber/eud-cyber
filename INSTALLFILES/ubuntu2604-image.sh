#!/usr/bin/env bash
# Only WAZUH5X and TPOT01 source this file. LINUX_IMG remains Ubuntu 24.04.
fetch_ubuntu2604() {
  local url="${UBUNTU2604_IMG:-https://cloud-images.ubuntu.com/resolute/20261108/resolute-server-cloudimg-amd64.img}"
  local digest="${UBUNTU2604_SHA256:-7b90593f5532b49b7e3fe3d2743f0d1f0d822e5b07cebcd8e00c0df8069ecab9}"
  [[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Invalid UBUNTU2604_SHA256' >&2; return 1; }
  if [[ -n "${UBUNTU2604_IMG:-}" && -z "${UBUNTU2604_SHA256:-}" ]]; then
    echo 'Custom Ubuntu 26.04 image requires UBUNTU2604_SHA256.' >&2
    return 1
  fi
  [[ "$url" == https://* || "$url" == http://* ]] || return 1
  mkdir -p IMAGES
  IMG_PATH="$(pwd)/IMAGES/resolute-${digest,,}.img"
  (
    flock -w 1800 8 || exit 1
    if [[ -f "$IMG_PATH" ]] && printf '%s  %s\n' "$digest" "$IMG_PATH" | sha256sum -c -; then
      exit 0
    fi
    local temporary
    temporary="$(mktemp "${IMG_PATH}.XXXXXX")"
    trap 'rm -f -- "$temporary"' EXIT
    curl --fail --location --retry 3 --connect-timeout 30 --max-time 1800 --output "$temporary" "$url"
    printf '%s  %s\n' "$digest" "$temporary" | sha256sum -c -
    qemu-img info "$temporary" | grep -q 'file format: qcow2'
    mv -- "$temporary" "$IMG_PATH"
  ) 8>"${IMG_PATH}.lock"
}
