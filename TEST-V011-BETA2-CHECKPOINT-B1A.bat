@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA2-CHECKPOINT-B1A.ps1"
exit /b %ERRORLEVEL%
