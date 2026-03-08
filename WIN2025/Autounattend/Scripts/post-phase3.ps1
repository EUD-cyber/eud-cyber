$log = "C:\Windows\Setup\Scripts\post-phase3.log"

function Log {
    param([string]$Message)
    $line = "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $Message"
    Write-Host $line
    $line | Out-File $log -Append -Encoding utf8
}

Start-Sleep -Seconds 45
Log "Starting phase 3..."

# DC should use itself for DNS
Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses "127.0.0.1" -ErrorAction SilentlyContinue

# marker
New-Item -ItemType File -Path "C:\Windows\Setup\Scripts\DONE.txt" -Force | Out-Null
Log "Created DONE marker."

# cleanup tasks
Unregister-ScheduledTask -TaskName "PostDCPhase2" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "PostDCPhase3" -Confirm:$false -ErrorAction SilentlyContinue
Log "Removed scheduled tasks."

Log "Shutting down VM..."
Stop-Computer -Force
