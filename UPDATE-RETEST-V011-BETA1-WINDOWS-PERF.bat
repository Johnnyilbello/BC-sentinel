@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\UPDATE-RETEST-V011-BETA1-WINDOWS-PERF.ps1"
exit /b %ERRORLEVEL%
