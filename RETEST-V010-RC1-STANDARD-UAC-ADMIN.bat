@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0RETEST-V010-RC1-STANDARD-UAC-ADMIN.ps1"
exit /b %errorlevel%
