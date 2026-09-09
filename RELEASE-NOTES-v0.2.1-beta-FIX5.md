# BC Sentinel v0.2.1-beta FIX5

Dedicated Windows taskbar icon patch.

- regenerated a multi-DPI ICO with 16/20/24/32/40/48/64/96/128/256 sizes;
- Qt uses the proven PNG asset for QApplication/MainWindow runtime icons;
- PyInstaller still embeds the ICO in BC-Sentinel.exe;
- Windows uses the stable `BCSentinel.Security` AppUserModelID;
- WM_SETICON now uses explicit pointer-sized x64 ctypes signatures;
- PyInstaller bundled runtime assets resolve through `sys._MEIPASS`;
- PyInstaller receives an absolute path for the executable ICO.

No ETW, scanner, scoring, ransomware or quarantine behavior changed.
