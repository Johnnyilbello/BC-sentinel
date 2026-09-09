@echo off
title BC Sentinel - Diagnostica Python
echo === PY LAUNCHER ===
py -0p
echo.
echo === WHERE PYTHON ===
where python
echo.
echo === WINGET ===
winget list --id Python.Python.3.12 --exact --source winget
echo.
echo === STANDARD PATHS ===
dir "%LOCALAPPDATA%\Programs\Python" /s /b 2>nul | findstr /i "\\python.exe$"
dir "%ProgramFiles%\Python*" /s /b 2>nul | findstr /i "\\python.exe$"
echo.
echo === REGISTRY HKCU ===
reg query "HKCU\Software\Python\PythonCore\3.12\InstallPath" /ve 2>nul
reg query "HKCU\Software\Python\PythonCore\3.12\InstallPath" /v ExecutablePath 2>nul
echo.
echo === REGISTRY HKLM ===
reg query "HKLM\Software\Python\PythonCore\3.12\InstallPath" /ve 2>nul
reg query "HKLM\Software\Python\PythonCore\3.12\InstallPath" /v ExecutablePath 2>nul
echo.
pause
