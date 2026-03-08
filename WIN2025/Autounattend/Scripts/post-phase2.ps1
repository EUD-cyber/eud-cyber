$log = "C:\Windows\Setup\Scripts\post-phase2.log"

function Log {
    param([string]$Message)
    $line = "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $Message"
    Write-Host $line
    $line | Out-File $log -Append -Encoding utf8
}

Log "Starting phase 2..."
Start-Sleep -Seconds 60

# =========================
# Install AD DS role with retry
# =========================
$adds = $null

for ($try = 1; $try -le 3; $try++) {
    Log "Installing AD DS role, attempt $try..."
    $adds = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction SilentlyContinue

    if ($adds.Success) {
        Log "AD DS role installed successfully."
        break
    }

    Log "AD DS install failed on attempt $try. ExitCode: $($adds.ExitCode)"
    Start-Sleep -Seconds 60
}

if (-not $adds -or -not $adds.Success) {
    Log "ERROR: AD DS role installation failed after retries."
    if ($adds) {
        ($adds | Format-List * | Out-String) | Out-File $log -Append -Encoding utf8
    }
    exit 1
}

Import-Module ADDSDeployment

# =========================
# Register phase 3 task
# =========================
$phase3Script = "C:\Windows\Setup\Scripts\post-phase3.ps1"

if (-not (Test-Path $phase3Script)) {
    Log "ERROR: Missing phase 3 script: $phase3Script"
    exit 1
}

Log "Registering phase 3 startup task..."

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$phase3Script`""

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "PostDCPhase3" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Force | Out-Null

# =========================
# Promote to DC
# =========================
$DomainName = "lab.local"
$SafeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

Log "Promoting server to Domain Controller..."

Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName "LAB" `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDNS `
    -Force `
    -Confirm:$false `
    -NoRebootOnCompletion:$false
