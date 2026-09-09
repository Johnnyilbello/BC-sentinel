# BC Sentinel v0.2.0-beta

- System tray with open, quick scan, protection and full exit.
- Closing the window can leave protection running in the tray.
- Autostart starts in background mode.
- Native Windows notifications via Windows-Toasts with tray fallback.
- Optional ETW process/file telemetry via pywintrace.
- File/process correlation and ransomware process attribution when available.
- Improved process tree.
- Persistence monitor for Run/RunOnce, Startup folders and Scheduled Tasks.
- Ollama connection test, configurable model and AI explanation in threat dialog.
- Persistent ETW/notification/tray/animation settings.
- Rotating structured JSONL logging and unified security-event journal.
- Stable core contracts designed so telemetry backends can later move to Rust/C++.
- Subtle page fades, pulsing protected-state indicator and dialog fade-ins.

ETW remains best-effort user-space telemetry. If unavailable or insufficiently
privileged, BC Sentinel keeps using psutil/watchdog fallbacks.
