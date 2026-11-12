# Nordic Manufacturing A/S - Defender ASR WMI Persistence Test
# Harmless lab test. Run in Windows PowerShell as Administrator.
param([switch]$Cleanup)

$ns = "root\subscription"
$filterName = "NordicASRTestFilter"
$consumerName = "NordicASRTestConsumer"
$marker = "C:\Users\Public\WMI-ASR-Test.txt"

function Remove-LabTest {
    Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
      Where-Object { $_.Filter -like "*$filterName*" -or $_.Consumer -like "*$consumerName*" } |
      Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='$consumerName'" -ErrorAction SilentlyContinue |
      Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue |
      Remove-WmiObject -ErrorAction SilentlyContinue
}

if ($Cleanup) {
    Remove-LabTest
    Remove-Item $marker -Force -ErrorAction SilentlyContinue
    Write-Host "Test ryddet op."
    exit
}

Remove-LabTest
Remove-Item $marker -Force -ErrorAction SilentlyContinue

Write-Host "Opretter ufarlig WMI event subscription..."

$filter = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{
    Name=$filterName
    EventNamespace="root\cimv2"
    QueryLanguage="WQL"
    Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
}

$consumer = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{
    Name=$consumerName
    CommandLineTemplate='cmd.exe /c echo WMI ASR test executed > C:\Users\Public\WMI-ASR-Test.txt'
}

Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{
    Filter=$filter
    Consumer=$consumer
} | Out-Null

Write-Host "Starter en ufarlig proces for at trigge testen..."
Start-Process notepad.exe
Start-Sleep -Seconds 8
Get-Process notepad -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if (Test-Path $marker) {
    Write-Host "RESULTAT: ALLOWED"
    Write-Host "Testfil oprettet: $marker"
} else {
    Write-Host "RESULTAT: Testfil blev IKKE oprettet."
    Write-Host "Kontroller Defender Operational-loggen for en ASR-haendelse."
}

Write-Host "Koer scriptet med -Cleanup naar testen er faerdig."
