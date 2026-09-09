@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0INSTALLA-SERVIZIO-TELEMETRIA.ps1" -Remove
