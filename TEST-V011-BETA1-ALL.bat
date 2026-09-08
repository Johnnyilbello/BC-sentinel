@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA1-ALL.ps1"
exit /b %ERRORLEVEL%
