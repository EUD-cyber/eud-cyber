@echo off
echo Running SetupComplete...

powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\Setup\Scripts\post.ps1"

exit /b 0
