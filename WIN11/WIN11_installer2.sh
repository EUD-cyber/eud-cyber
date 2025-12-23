#!/bin/bash

LOGFILE="$(pwd)/LOGS/WIN11.log"

# Create log file and ensure permissions
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Redirect all output (stdout + stderr) to log AND console
exec > >(tee -a "$LOGFILE") 2>&1

echo "===== WIN11 installation started at $(date) ====="

START_VMID=100
BASE_NAME="WIN11"
USERNAME="lab"
PASSWORD="Password!1"
IMG_NAME="WinDevEval.VMWare.zip"
IMG_PATH="$(pwd)/WinDevEval.VMWare.zip"
IMG_PATH2="$(pwd)/WinDev2407Eval-disk1.vmdk"
IMG_URL="https://aka.ms/windev_VM_vmware"
VIRT_PATH="/var/lib/vz/template/iso/virtio-win.iso"
VIRT_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
VMSTORAGE="local-lvm" # Where should the VM saved on Proxmox
BRIDGE="lan1" # Your network definition for VM
BRIDGE="lan2"
VIRTIO_ISO="ISOimages:iso/virtio-win.iso" # Location of virtio driver ISO
OVF="$(pwd)/WinDev2407Eval.ovf"


# ===== Download Windows 11 if missing =====
if [[ ! -f "IMG_PATH" ]]; then
    if [[ ! -f "IMG_PATH2" ]]; then
        echo "Neither file exists, downloading..."
        wget --show-progress -O "$IMG_PATH" "$IMG_URL"
    else
        echo "$IMG_PATH2 exits, skipping download"
    fi
else
    echo "$IMG_PATH exists, skipping download"
fi

if [  -f "$IMG_PATH" ]; then
    echo "Unzipping $IMG_PATH IMG..."
    unzip -o $IMG_PATH
    rm $IMG_PATH
else
    echo "File allready unzipped exists"
fi

if [ ! -f "$VIRT_PATH" ]; then
        echo "[+] Downloading VirtIO drivers"
        wget -O "$VIRT_PATH" "$VIRT_URL"
else
    echo "$VIRT_PATH allready exists"
fi

# ===== Find next free VMID =====
VMID=$START_VMID
while qm status $VMID &>/dev/null; do
    VMID=$((VMID + 1))
done
echo "Selected free VMID: $VMID"

# ===== Handle VM name collision =====
VM_NAME="$BASE_NAME"
COUNT=1
while qm list | awk '{print $2}' | grep -x "$VM_NAME" &>/dev/null; do
    VM_NAME="${BASE_NAME}-${COUNT}"
    COUNT=$((COUNT + 1))
done
echo "VM name to use: $VM_NAME"

echo "[i] Importing VM into Proxmox..."
qm importovf $VMID $OVF $VMSTORAGE --format raw
qm set $VMID \
  --name "$VM_NAME" \
  --bois ovmf \
  --cpu host \
  --net0 virtio,bridge=$BRIDGE \
  --net1 virtio,bridge=$BRIDGE1 \
  --ostype win11 \
  --machine pc-q35-8.1 \
  --agent 1,fstrim_cloned_disks=1 \
  --ide2 media=cdrom,file=$VIRTIO_ISO \
  --boot order='sata0;ide2' \
  --efidisk0 $VMSTORAGE:1,efitype=4m,pre-enrolled-keys=1,size=4M \
  --tpmstate0 $VMSTORAGE:1,size=4M,version=v2.0 \
qm start $VMID

echo "[!] PLEASE install VIRTIO driver package from CD ROM on your newly created VM!"

while true; do
    RESULT=$(qm guest cmd $VMID ping)
    if [ $? -eq 0 ]; then
        echo "[i] QEMU agent seems to run on the new VM."
        break
    fi

    echo "[-] Waiting another 30 seconds until VIRTIO drivers are installed and QEMU agent is running..."
    sleep 30
done

echo "[-] Waiting another 30 seconds to make sure everything is ready before proceeding..."
sleep 30

if [ -n "$USERNAME" ]; then
    echo "[i] Adding additional user to the system..."
    RESULT=$(qm guest exec $VMID -- Powershell.exe -Command '$Password = ConvertTo-SecureString "'$PASSWORD'" -AsPlainText -Force; New-LocalUser -Name "'$USERNAME'" -Password $Password; Add-LocalGroupMember -Group "Administrators" -Member "'$USERNAME'"')
fi

echo "[i] Preparing system so it can be managed by Ansible later on..."
RESULT=$(qm guest exec $VMID -- Powershell.exe -Command '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = "https://raw.githubusercontent.com/AlexNabokikh/windows-playbook/master/setup.ps1"; $file = "$env:temp\setup.ps1"; (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file); powershell.exe -ExecutionPolicy ByPass -File $file -Verbose')

max_attempts=50
attempt=1

# Loop for maximum attempts
while [ $attempt -le $max_attempts ]; do
    # Run the command and capture its output (due OpenSSH install attempt with
    # PowerShell we will check if it is finished. Means only one PowerShell process
    # is running: The one we use to count the PowerShell processes.
    RESULT=$(qm guest exec $VMID -- PowerShell.exe -Command 'if((Get-Process -Name "powershell" | Measure-Object).Count -eq 1) { Write-Output "ready-for-reboot" }')

   # Check if the output contains "out-data"
    if [[ $RESULT == *"ready-for-reboot"* ]]; then
        echo "[i] OpenSSH Server Stage 1 successfully installed; now reboot required."
        break
    else
        echo "[i] OpenSSH Server (still) not running (attempt: $attempt). Retrying in 30 seconds..."
        ((attempt++))
        sleep 30
    fi
done

echo "[i] Removing virtio CD image from system (has to be rebooted for this task)"
qm shutdown $VMID
qm set $VMID --ide2 media=cdrom,file=none
qm start $VMID

# Now we have to install OpenSSH again to enforce daemon...
echo "[i] Preparing system so it can be managed by Ansible later on..."
RESULT=$(qm guest exec $VMID -- Powershell.exe -Command '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = "https://raw.githubusercontent.com/AlexNabokikh/windows-playbook/master/setup.ps1"; $file = "$env:temp\setup.ps1"; (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file); powershell.exe -ExecutionPolicy ByPass -File $file -Verbose')

max_attempts=20
attempt=1

# Loop for maximum attempts
while [ $attempt -le $max_attempts ]; do
    # Run the command and capture its output
    RESULT=$(qm guest exec $VMID -- PowerShell.exe -Command 'Get-Process sshd')

    # Check if the output contains "out-data"
    if [[ $RESULT == *"out-data"* ]]; then
        echo "[i] OpenSSH Server successfully installed and it is running."
        break
    else
        echo "[-] OpenSSH Server (still) not running (attempt: $attempt). Retrying in 30 seconds..."
        ((attempt++))
        sleep 30
    fi
done

echo "[!] Basics done (VM deployed, User added, OpenSSH Server installed and running)."
