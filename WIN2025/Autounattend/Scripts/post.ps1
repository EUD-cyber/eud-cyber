Write-Host "Starting post configuration..."

# =========================
# Wait for NICs
# =========================
Write-Host "Waiting for network adapters..."

for ($i=0; $i -lt 30; $i++) {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object ifIndex
    if ($adapters.Count -ge 2) { break }
    Start-Sleep -Seconds 2
}

if ($adapters.Count -lt 2) {
    Write-Host "ERROR: Expected at least 2 NICs, found $($adapters.Count)."
} else {

    $nic1 = $adapters[0].Name
    $nic2 = $adapters[1].Name

    Write-Host "Detected NIC1: $nic1"
    Write-Host "Detected NIC2: $nic2"

    # Rename NICs
    Write-Host "Renaming NICs..."
    Rename-NetAdapter -Name $nic1 -NewName "LAN" -PassThru -ErrorAction SilentlyContinue
    Rename-NetAdapter -Name $nic2 -NewName "OOB" -PassThru -ErrorAction SilentlyContinue

    $nic1 = "LAN"
    $nic2 = "OOB"

    # Disable IPv6
    Write-Host "Disabling IPv6..."
    Disable-NetAdapterBinding -Name $nic1 -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Disable-NetAdapterBinding -Name $nic2 -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue

    # LAN IP
    Write-Host "Configuring NIC1 (LAN)..."
    Set-NetIPInterface -InterfaceAlias $nic1 -Dhcp Disabled -ErrorAction SilentlyContinue
    Get-NetIPAddress -InterfaceAlias $nic1 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $nic1 -IPAddress "192.168.2.22" -PrefixLength 24 -DefaultGateway "192.168.2.1" -AddressFamily IPv4
    Set-DnsClientServerAddress -InterfaceAlias $nic1 -ServerAddresses "192.168.2.1"

    # OOB IP
    Write-Host "Configuring NIC1 (OOB)..."
    Set-NetIPInterface -InterfaceAlias $nic2 -Dhcp Disabled -ErrorAction SilentlyContinue
    Get-NetIPAddress -InterfaceAlias $nic2 -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $nic2 -IPAddress "172.20.0.22" -PrefixLength 24 -AddressFamily IPv4
    Set-DnsClientServerAddress -InterfaceAlias $nic2 -ResetServerAddresses
}

# Rename host
$targetName = "WIN2025"
if ((hostname) -ne $targetName) {
    Write-Host "Renaming computer to $targetName..."
    Rename-Computer -NewName $targetName -Force
}

# Enable RDP
Write-Host "Enabling RDP..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# install domain service and config lab.local
Write-Host "Installing AD DS role..."
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Import-Module ADDSDeployment

$DomainName = "lab.local"
$SafeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

Write-Host "Promoting server to Domain Controller..."

Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName "LAB" `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDns `
    -Force `
    -NoRebootOnCompletion:$false
