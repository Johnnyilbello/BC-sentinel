# BC Sentinel v0.2.1-beta FIX7

Dedicated fix for the main Windows taskbar button icon.

The tray icon was already correct, proving the BC Sentinel asset was valid.
The remaining generic icon belonged to the top-level Qt/Python window.

FIX7:
- sends `WM_SETICON` to the real HWND;
- also updates the window-class icons via `GCLP_HICON` and `GCLP_HICONSM`;
- uses pointer-sized Win32 ctypes signatures on 64-bit Windows;
- applies the icon at 0 ms, 150 ms and 700 ms after first show so Qt/Explorer
  cannot overwrite it during initial window creation;
- keeps HICON handles alive for the window lifetime;
- applies AppUserModelID only to the frozen BC-Sentinel.exe, not source runs.

Tray, ETW, Telemetry Service, scanning, quarantine and scoring are unchanged.
