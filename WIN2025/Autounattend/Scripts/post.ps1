Write-Host "Starting post configuration..."

$ErrorActionPreference = "Continue"

# =========================
# Wait for NICs
# =========================
Write-Host "Waiting for network adapters..."

$adapters = $null
for ($i = 0; $i -lt 30; $i++) {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -ne "Disabled" } |
        Sort-Object ifIndex

    if ($adapters.Count -ge 2) { break }
    Start-Sleep -Seconds 2
}

if ($adapters.Count -lt 2) {
    Write-Host "ERROR: Expected at least 2 NICs, found $($adapters.Count)."
    exit 1
}

$nic1 = $adapters[0].Name
$nic2 = $adapters[1].Name

Write-Host "Detected NIC1: $nic1"
Write-Host "Detected NIC2: $nic2"

# =========================
# Rename NICs
# =========================
Write-Host "Renaming NICs..."
if ($nic1 -ne "LAN") {
    Rename-NetAdapter -Name $nic1 -NewName "LAN" -PassThru -ErrorAction SilentlyContinue | Out-Null
}
if ($nic2 -ne "OOB") {
    Rename-NetAdapter -Name $nic2 -NewName "OOB" -PassThru -ErrorAction SilentlyContinue | Out-Null
}

$nic1 = "LAN"
$nic2 = "OOB"

Start-Sleep -Seconds 5

# =========================
# Disable IPv6
# =========================
Write-Host "Disabling IPv6..."
Disable-NetAdapterBinding -Name $nic1 -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name $nic2 -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue

# =========================
# Configure LAN
# =========================
Write-Host "Configuring NIC1 (LAN)..."
Set-NetIPInterface -InterfaceAlias $nic1 -Dhcp Disabled -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceAlias $nic1 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceAlias $nic1 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $nic1 -IPAddress "192.168.2.22" -PrefixLength 24 -DefaultGateway "192.168.2.1" -AddressFamily IPv4 -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceAlias $nic1 -ServerAddresses "192.168.2.1" -ErrorAction SilentlyContinue

# =========================
# Configure OOB
# =========================
Write-Host "Configuring NIC2 (OOB)..."
Set-NetIPInterface -InterfaceAlias $nic2 -Dhcp Disabled -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceAlias $nic2 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceAlias $nic2 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $nic2 -IPAddress "172.20.0.22" -PrefixLength 24 -AddressFamily IPv4 -ErrorAction Stop
Set-DnsClientServerAddress -InterfaceAlias $nic2 -ResetServerAddresses -ErrorAction SilentlyContinue

# =========================
# Enable RDP
# =========================
Write-Host "Enabling RDP..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

# =========================
# Register phase 2 task
# =========================
Write-Host "Registering phase 2 startup task..."

$phase2Script = "C:\Windows\Setup\Scripts\post-phase2.ps1"

if (-not (Test-Path $phase2Script)) {
    Write-Host "ERROR: Missing phase 2 script: $phase2Script"
    exit 1
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$phase2Script`""

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "PostDCPhase2" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Force | Out-Null

# =========================
# Rename host if needed
# =========================
$targetName = "WIN2025"
$renameNeeded = ((hostname) -ne $targetName)

if ($renameNeeded) {
    Write-Host "Renaming computer to $targetName..."
    Rename-Computer -NewName $targetName -Force

    Write-Host "Computer rename pending. Rebooting now..."
    Restart-Computer -Force
    exit 0
}

# If no rename needed, go straight to phase 2
Write-Host "No rename reboot needed. Starting phase 2 directly..."
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Windows\Setup\Scripts\post-phase2.ps1"
exit $LASTEXITCODE
