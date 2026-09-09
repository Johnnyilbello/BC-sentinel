@echo off
title BC Sentinel - Crea EXE
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap.ps1" -Build
if errorlevel 1 pause
