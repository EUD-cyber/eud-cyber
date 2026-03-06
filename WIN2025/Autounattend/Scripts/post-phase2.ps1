Start-Sleep -Seconds 30

"Phase 2 started: $(Get-Date)" | Out-File C:\Windows\Setup\Scripts\post-phase2.log -Append

# DC should use itself for DNS
Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses "127.0.0.1"

# marker file
New-Item -ItemType File -Path C:\Windows\Setup\Scripts\DONE.txt -Force | Out-Null

# remove task so it only runs once
Unregister-ScheduledTask -TaskName "PostDCFinish" -Confirm:$false -ErrorAction SilentlyContinue

"Phase 2 finished: $(Get-Date)" | Out-File C:\Windows\Setup\Scripts\post-phase2.log -Append

Stop-Computer -Force
