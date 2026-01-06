@echo off
echo SetupComplete starting... > C:\Windows\Setup\Scripts\post.log

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Windows\Setup\Scripts\post.ps1" >> C:\Windows\Setup\Scripts\post.log 2>&1

echo Done. >> C:\Windows\Setup\Scripts\post.log
exit /b 0
