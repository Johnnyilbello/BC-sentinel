# BC Sentinel v0.1.5 — Stitch v2 UI Integration

This release integrates the user-provided Stitch v2 design direction into the real PySide6 application while preserving the validated BC Sentinel detection backend.

## UI
- professional fixed desktop sidebar: Dashboard, Scansione, Quarantena, Cronologia, Protezione, Impostazioni;
- Stitch-derived charcoal/emerald design tokens;
- Stitch app icon integrated into the app and Windows build;
- redesigned dashboard, scan workflow, quarantine, history, protection and settings pages;
- custom threat dialog that displays only real engine evidence;
- no Enterprise Shield, account, support, VPN, firewall or fictional protection claims;
- AI Security Analyst explicitly marked Beta/optional;
- history retains one current state per SHA-256.

## Functional improvements
- real-time detections are marshalled safely to the Qt UI thread through signals;
- realtime, ransomware and behavior toggles are functional and persisted;
- monitored folders are configurable and persisted;
- allowlist file/directory management is available in Settings;
- Windows autostart is implemented via the current-user Run registry key;
- build includes the BC Sentinel icon and application assets.

## Important limitation
BC Sentinel v0.1.5 remains user-space MVP protection. Microsoft Defender should remain enabled while testing. No kernel driver, proprietary firewall, memory scanner, boot-sector scanner or guaranteed pre-execution blocking is claimed.
