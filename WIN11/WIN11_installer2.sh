#!/bin/bash

USERNAME= lab
PASSWORD= Password!1
VMNAME= WIN11
VMDOWNLOAD_PATH="/mnt/pve/ISOimages" # Where to download the Windows 11 Developer Image
VMSTORAGE="FastDisk" # Where should the VM saved on Proxmox
VMNET="virtio,bridge=lan1" # Your network definition for VM
VIRTIO_ISO="ISOimages:iso/virtio-win.iso" # Location of virtio driver ISO
# --- End Config Section

echo "[i] Downloading VM image"
cd $VMDOWNLOAD_PATH
wget -O WinDevEval.VMWare.zip https://aka.ms/windev_VM_vmware
unzip -o WinDevEval.VMWare.zip
rm WinDevEval.VMWare.zip

vmid=110
echo "[i] Importing VM into Proxmox..."
latestOVF=$(ls -Art WinDev*.ovf | tail -n 1)
echo "[i] Next VM ID: $vmid, OVF template: $latestOVF"
qm importovf $vmid $latestOVF $VMSTORAGE --format raw
[ -z "$VMNAME" ] && VMNAME=${latestOVF%.*}
qm set $vmid --name $VMNAME
qm set $vmid --bios ovmf
qm set $vmid --cpu host
qm set $vmid --machine pc-q35-8.1
qm set $vmid --agent 1,fstrim_cloned_disks=1
sed -i 's/scsi0:/sata0:/' /etc/pve/qemu-server/$vmid.conf
sed -i 's/sata0:.*/&,discard=on/' /etc/pve/qemu-server/$vmid.conf
qm set $vmid --ide2 media=cdrom,file=$VIRTIO_ISO
qm set $vmid --boot order='sata0;ide2'
qm set $vmid --ostype win11
qm set $vmid --net0 $VMNET
qm set $vmid --efidisk0 $VMSTORAGE:1,efitype=4m,pre-enrolled-keys=1,size=4M
qm set $vmid --tpmstate0 $VMSTORAGE:1,size=4M,version=v2.0
qm start $vmid

echo "[!] PLEASE install VIRTIO driver package from CD ROM on your newly created VM!"

while true; do
    RESULT=$(qm guest cmd $vmid ping)
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
    RESULT=$(qm guest exec $vmid -- Powershell.exe -Command '$Password = ConvertTo-SecureString "'$PASSWORD'" -AsPlainText -Force; New-LocalUser -Name "'$USERNAME'" -Password $Password; Add-LocalGroupMember -Group "Administrators" -Member "'$USERNAME'"')
fi

echo "[i] Preparing system so it can be managed by Ansible later on..."
RESULT=$(qm guest exec $vmid -- Powershell.exe -Command '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = "https://raw.githubusercontent.com/AlexNabokikh/windows-playbook/master/setup.ps1"; $file = "$env:temp\setup.ps1"; (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file); powershell.exe -ExecutionPolicy ByPass -File $file -Verbose')

max_attempts=50
attempt=1

# Loop for maximum attempts
while [ $attempt -le $max_attempts ]; do
    # Run the command and capture its output (due OpenSSH install attempt with
    # PowerShell we will check if it is finished. Means only one PowerShell process
    # is running: The one we use to count the PowerShell processes.
    RESULT=$(qm guest exec $vmid -- PowerShell.exe -Command 'if((Get-Process -Name "powershell" | Measure-Object).Count -eq 1) { Write-Output "ready-for-reboot" }')

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
qm shutdown $vmid
qm set $vmid --ide2 media=cdrom,file=none
qm start $vmid

# Now we have to install OpenSSH again to enforce daemon...
echo "[i] Preparing system so it can be managed by Ansible later on..."
RESULT=$(qm guest exec $vmid -- Powershell.exe -Command '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $url = "https://raw.githubusercontent.com/AlexNabokikh/windows-playbook/master/setup.ps1"; $file = "$env:temp\setup.ps1"; (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file); powershell.exe -ExecutionPolicy ByPass -File $file -Verbose')

max_attempts=20
attempt=1

# Loop for maximum attempts
while [ $attempt -le $max_attempts ]; do
    # Run the command and capture its output
    RESULT=$(qm guest exec $vmid -- PowerShell.exe -Command 'Get-Process sshd')

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
