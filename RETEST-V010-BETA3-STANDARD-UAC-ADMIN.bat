@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0RETEST-V010-BETA3-STANDARD-UAC-ADMIN.ps1"
exit /b %errorlevel%
