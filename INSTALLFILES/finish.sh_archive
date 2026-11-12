#!/bin/bash

SNAP_PREFIX="auto-snap"
DESC="First_snapshot"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M")

VMIDS=$(qm list | awk 'NR>1 {print $1}')

for VMID in $VMIDS; do
  echo "[+] Creating snapshot for VMID $VMID..."
  qm snapshot "$VMID" "${SNAP_PREFIX}-${TIMESTAMP}" \
    --description "$DESC" || echo "[!] Snapshot failed for VMID $VMID"
done

echo "[✓] All VM snapshots completed"
