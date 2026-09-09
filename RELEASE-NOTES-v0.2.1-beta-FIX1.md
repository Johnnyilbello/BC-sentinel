# BC Sentinel v0.2.1-beta FIX1

Fixes the immediate startup failure seen on Windows.

Root cause:
`app/main.py` uses `os.name` while configuring the Windows AppUserModelID,
but the v0.2.1 Beta source did not import the `os` module.

This caused a `NameError` before QApplication/MainWindow could start.

Changes:
- add the missing `import os`;
- remove a duplicated `QIcon` import;
- improve `bootstrap.ps1` so future Python tracebacks are printed and appended
  to `BC-Sentinel-install.log` instead of showing only "exit code 1";
- add regression tests for the startup path.

No scanner, ETW, telemetry service, ransomware, quarantine or scoring logic
was changed.
