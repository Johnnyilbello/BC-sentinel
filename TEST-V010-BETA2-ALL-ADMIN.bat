@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0TEST-V010-BETA2-ALL-ADMIN.ps1"
exit /b %errorlevel%
