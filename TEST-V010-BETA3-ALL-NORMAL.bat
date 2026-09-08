@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0TEST-V010-BETA3-ALL-NORMAL.ps1"
exit /b %errorlevel%
