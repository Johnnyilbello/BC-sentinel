@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\UPDATE-TEST-V011-BETA1.ps1"
exit /b %ERRORLEVEL%
