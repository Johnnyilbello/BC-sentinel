# BC Sentinel v0.2.1-beta FIX3

## Taskbar icon
- during source runs BC Sentinel no longer assigns an unregistered Windows
  AppUserModelID, which could make Explorer show a generic taskbar icon;
- the frozen PyInstaller EXE still uses the explicit AppUserModelID;
- the ICO is now the single canonical QApplication icon;
- MainWindow also sends `WM_SETICON` directly to its HWND using the 32x32 and
  16x16 images from `bc_sentinel.ico`.

## Windows-safe automated tests
Automated tests no longer place the canonical EICAR antivirus test signature on
disk. Microsoft Defender or another installed antivirus can legitimately remove
that file before pytest reads it, causing a false build failure.

Coverage is preserved:
- canonical EICAR matching is tested in memory;
- scanner CRITICAL/100 scoring is exercised with a harmless simulated marker;
- scanner -> detection -> quarantine -> restore remains covered end-to-end.

The canonical EICAR file remains a manual acceptance test only.

## Better build diagnostics
`CREA-EXE.bat` / `bootstrap.ps1 -Build` now captures complete pytest stdout and
stderr. If any Windows-only test still fails, the exact failing test and
traceback are printed and copied to `BC-Sentinel-install.log`.

The main PyInstaller build is also checked before the Telemetry Service build is
started.
