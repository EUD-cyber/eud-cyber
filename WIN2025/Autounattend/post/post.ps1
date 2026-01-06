# =========================
# CONFIG - EDIT THESE
# =========================

$NewHostname   = "WIN2025-DC01"

$InterfaceName = "Ethernet"
$IPv4Address   = "192.168.1.50"
$PrefixLength  = 24
$Gateway       = "192.168.1.1"
$DnsServers    = @("192.168.1.10","1.1.1.1")

$JoinDomain    = $true
$DomainName    = "lab.local"
$DomainUser    = "LAB\\Administrator"
$DomainPass    = "Password1!"     # consider updating later via LAPS or secrets

$InstallAD     = $true
$SafeModePass  = "Password1!"     # DSRM password for AD

$CreateLocalUsers = @(
    @{User="opsuser";  Password="Password1!"; Admin=$true},
    @{User="helpdesk"; Password="Password1!"; Admin=$false}
)

# =========================
# START
# =========================

Write-Host "Post install script running..."

# Rename computer
if ((hostname) -ne $NewHostname) {
    Rename-Computer -NewName $NewHostname -Force
}

# Static IP
Write-Host "Configuring networking..."
Get-NetAdapter -Name $InterfaceName -ErrorAction Stop |
    Set-NetIPInterface -Dhcp Disabled -ErrorAction Stop

New-NetIPAddress `
    -InterfaceAlias $InterfaceName `
    -IPAddress $IPv4Address `
    -PrefixLength $PrefixLength `
    -DefaultGateway $Gateway `
    -ErrorAction SilentlyContinue

Set-DnsClientServerAddress `
    -InterfaceAlias $InterfaceName `
    -ServerAddresses $DnsServers

# Enable RDP
Write-Host "Enabling RDP..."
Set-ItemProperty `
  -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
  -Name fDenyTSConnections `
  -Value 0

Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Create local users
foreach ($u in $CreateLocalUsers) {
    $secure = ConvertTo-SecureString $u.Password -AsPlainText -Force

    if (-not (Get-LocalUser -Name $u.User -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $u.User -Password $secure -FullName $u.User -PasswordNeverExpires $true
    }

    if ($u.Admin) {
        Add-LocalGroupMember -Group "Administrators" -Member $u.User -ErrorAction SilentlyContinue
    }
}

# Install AD DS (optional)
if ($InstallAD) {
    Write-Host "Installing AD DS..."
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

    if ($JoinDomain) {
        Write-Host "Promoting to domain controller..."
        Install-ADDSForest `
            -DomainName $DomainName `
            -SafeModeAdministratorPassword (ConvertTo-SecureString $SafeModePass -AsPlainText -Force) `
            -InstallDNS `
            -Force
    }
}

# Join domain (if not installing AD)
if ($JoinDomain -and -not $InstallAD) {
    $sec = ConvertTo-SecureString $DomainPass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($DomainUser,$sec)

    Add-Computer -DomainName $DomainName -Credential $cred -Force
}

Write-Host "Rebooting..."
Restart-Computer -Force
