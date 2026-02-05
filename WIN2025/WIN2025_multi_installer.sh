#!/bin/bash
set -e

LAB="$1"

if [[ -z "$LAB" ]] || ! [[ "$LAB" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <lab-number>"
  exit 1
fi

LOGDIR="$(pwd)/LOGS"
mkdir -p "$LOGDIR"
LOGFILE="$LOGDIR/WIN2025_lab${LAB}.log"

touch "$LOGFILE"
chmod 600 "$LOGFILE"

exec > >(tee -a "$LOGFILE") 2>&1

echo "===== WIN2025 installation started at $(date) ====="

# ===== CONFIG =====
START_VMID=$((LAB * 100))
BASE_NAME="lab${LAB}-WIN2025"

ISO_STORAGE="local"
DISK_STORAGE="local-lvm"

IMG_URL="https://go.microsoft.com/fwlink/?linkid=2345730&clcid=0x409&culture=en-us&country=us"
IMG_NAME="en-us_windows_server_2025_x64_dvd.iso"

VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.285-1/virtio-win-0.1.285.iso"

VIRTIO_NAME="virtio-win.iso"

ISO_DIR="/var/lib/vz/template/iso"
IMG_PATH="$(pwd)/IMAGES/$IMG_NAME"
VIRTIO_PATH="$(pwd)/IMAGES/$VIRTIO_NAME"

DST_WIN2025_PATH="$ISO_DIR/$IMG_NAME"
DST_VIRTIO_PATH="$ISO_DIR/$VIRTIO_NAME"

AUTO_FOLDER="$(pwd)/WIN2025/Autounattend"
AUTOISO_NAME="Autounattend_lab${LAB}.iso"
AUTOISO_PATH="$ISO_DIR/$AUTOISO_NAME"

NOPROMPT_NAME="en-us_windows_server_2025_noprompt.iso"
NOPROMPT_PATH="$ISO_DIR/$NOPROMPT_NAME"

MEMORY=8192
CORES=4
DISK_SIZE="40"

BRIDGE="lab${LAB}_lan2"
BRIDGE1="lab${LAB}_oobm"

# ===== Find next free VMID in lab range =====
VMID=$START_VMID
while qm status $VMID &>/dev/null; do
  VMID=$((VMID + 1))
done
echo "Selected VMID: $VMID"

# ===== VM name collision handling =====
VM_NAME="$BASE_NAME"
COUNT=1
while qm list | awk '{print $2}' | grep -x "$VM_NAME" &>/dev/null; do
  VM_NAME="${BASE_NAME}-${COUNT}"
  COUNT=$((COUNT + 1))
done
echo "VM name: $VM_NAME"

# ===== Download ISOs =====
mkdir -p "$(pwd)/IMAGES"

if [[ ! -f "$IMG_PATH" ]]; then
  echo "Downloading Windows ISO..."
  wget --show-progress -O "$IMG_PATH" "$IMG_URL"
fi

if [[ ! -f "$VIRTIO_PATH" ]]; then
  echo "Downloading VirtIO ISO..."
  wget --show-progress -O "$VIRTIO_PATH" "$VIRTIO_URL"
fi

# ===== Copy ISOs to Proxmox =====
[[ -f "$DST_WIN2025_PATH" ]] || cp "$IMG_PATH" "$DST_WIN2025_PATH"
[[ -f "$DST_VIRTIO_PATH" ]] || cp "$VIRTIO_PATH" "$DST_VIRTIO_PATH"

# ===== Build Autounattend ISO (lab-specific) =====
if [[ ! -f "$AUTOISO_PATH" ]]; then
  echo "Creating Autounattend ISO..."
  genisoimage -o "$AUTOISO_PATH" -J -R "$AUTO_FOLDER"
fi

# Build NO-PROMPT ISO via Ansible
# =======================

if [[ ! -f "$NOPROMPT_IMG_PATH" ]]; then
  echo "Creating no-prompt Windows ISO with Ansible..."

PLAYBOOK="/tmp/noprompt-iso.yml"

  cat > "$PLAYBOOK" <<'EOF'
- name: Build Windows No-Prompt ISO
  hosts: localhost
  become: true
  gather_facts: false

  vars:
    iso_source: "{{ lookup('env', 'SRC_ISO') }}"
    iso_output: "{{ lookup('env', 'DST_ISO') }}"
    iso_mount: "/dev/shm/winiso/mount"
    iso_extracted: "/dev/shm/winiso/extracted"
    volume_label: "WINSETUP"

  tasks:
    - name: Create workspace
      file:
        path: "{{ item }}"
        state: directory
      loop:
        - "{{ iso_mount }}"
        - "{{ iso_extracted }}"

    - name: Mount ISO
      mount:
        path: "{{ iso_mount }}"
        src: "{{ iso_source }}"
        fstype: udf
        opts: loop,ro
        state: mounted

    - name: Copy ISO contents
      synchronize:
        src: "{{ iso_mount }}/"
        dest: "{{ iso_extracted }}/"
        archive: true

    - name: Unmount ISO
      mount:
        path: "{{ iso_mount }}"
        state: unmounted

    - name: Ensure noprompt EFI file exists
      stat:
        path: "{{ iso_extracted }}/efi/microsoft/boot/efisys_noprompt.bin"
      register: noprompt

    - name: Abort if noprompt file missing
      fail:
        msg: "ISO has no efisys_noprompt.bin — cannot safely modify."
      when: not noprompt.stat.exists

    - name: Replace efisys.bin
      copy:
        remote_src: true
        src: "{{ iso_extracted }}/efi/microsoft/boot/efisys_noprompt.bin"
        dest: "{{ iso_extracted }}/efi/microsoft/boot/efisys.bin"

    - name: Replace cdboot.efi
      copy:
        remote_src: true
        src: "{{ iso_extracted }}/efi/microsoft/boot/cdboot_noprompt.efi"
        dest: "{{ iso_extracted }}/efi/microsoft/boot/cdboot.efi"

    - name: Build new ISO
      shell: |
        xorriso -as mkisofs \
          -iso-level 3 \
          -volid "{{ volume_label }}" \
          -eltorito-boot boot/etfsboot.com \
            -eltorito-catalog boot/boot.cat \
            -no-emul-boot \
            -boot-load-size 8 \
            -boot-info-table \
          -eltorito-alt-boot \
            -e efi/microsoft/boot/efisys.bin \
            -no-emul-boot \
          -isohybrid-gpt-basdat \
          -o "{{ iso_output }}" \
          "{{ iso_extracted }}"
    - name: Cleanup workspace
      file:
        path: "/dev/shm/winiso"
        state: absent
EOF

  # Run playbook with environment variables
  SRC_ISO="$DST_WIN2025_PATH" DST_ISO="$NOPROMPT_IMG_PATH" ansible-playbook "$PLAYBOOK"

else
  echo "No-prompt ISO already exists: $NOPROMPT_IMG_PATH"
fi

echo "Done."

# ===== Create VM =====
qm create $VMID \
  --name "$VM_NAME" \
  --memory $MEMORY \
  --cores $CORES \
  --cpu host \
  --net0 vmxnet3,bridge=$BRIDGE \
  --net1 vmxnet3,bridge=$BRIDGE1 \
  --scsihw virtio-scsi-pci \
  --ostype win11

qm set $VMID --scsi0 $DISK_STORAGE:$DISK_SIZE

qm set $VMID \
  --ide1 $ISO_STORAGE:iso/$NOPROMPT_NAME,media=cdrom \
  --ide2 $ISO_STORAGE:iso/$VIRTIO_NAME,media=cdrom \
  --ide3 $ISO_STORAGE:iso/$AUTOISO_NAME,media=cdrom

qm set $VMID \
  --boot order="scsi0;ide1" \
  --machine q35 \
  --bios ovmf \
  --efidisk0 $DISK_STORAGE:0,efitype=4m,ms-cert=2023,pre-enrolled-keys=1 \
  --tpmstate0 $DISK_STORAGE:0,version=v2.0 \
  --tablet 0 \
  --onboot 1

qm enroll-efi-keys $VMID

# ===== Snapshot =====
qm snapshot $VMID First_snapshot \
  --description "Clean baseline snapshot for lab reset"

# ===== Start VM =====
qm start $VMID

echo "WIN2025 VM $VMID ($VM_NAME) started successfully!"
