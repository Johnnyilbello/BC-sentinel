# BC Sentinel v0.6.1-beta.1 — Protection Service Hardening & Tamper Resistance

v0.6.1 hardens the Windows-accepted v0.6.0-beta.3 service architecture.

## Beta.1 Windows integrity-cache fix

- replaces Windows `st_ctime_ns` cache identity with native `FILE_BASIC_INFO.ChangeTime`;
- prevents same-size + restored-mtime protected-file modifications from reusing a stale digest;
- fails safe to re-hashing whenever Windows ChangeTime cannot be obtained;
- adds `protection-integrity-timestamp-evasion` to native Windows acceptance;
- adds explicit fail-safe regression coverage for ChangeTime lookup failure.

## Added

- canonical Protection Service deployment to `%ProgramFiles%\BC Sentinel\Protection`;
- recursive Program Files/ProgramData ACL hardening;
- split IPC token vs machine-private HMAC integrity key;
- safe migration of valid v0.6.x signed config;
- SHA-256 frozen-tree manifest + post-deployment HMAC sealing;
- sealed startup integrity gate;
- periodic install/config/ACL/SCM/audit self-protection monitor;
- same-size/same-mtime-resistant integrity cache metadata + periodic forced full hash;
- unexpected executable/rule/reparse-point tamper detection;
- HMAC hash-chained privileged/lifecycle audit with truncation detection;
- SCM lifecycle audit;
- UI degraded-hardening state;
- `hardening_status` read-only IPC operation;
- Windows `protection-hardening-foundation` + `protection-hardening-live` acceptance gates;
- service idle/IPC/event-storm benchmark;
- real reboot persistence arm/verify acceptance tool.

## Preserved

- authenticated Windows Named Pipe IPC;
- kernel-derived client identity fallback;
- admin gate for privileged mutation;
- Behavior Correlation v2;
- incident response foundation;
- ETW/network/realtime/persistence stack;
- encrypted quarantine;
- GUI fallback behavior when service is unavailable.

## Development verification

- 227/227 tests PASS;
- compileall PASS;
- synthetic 5,000-file scanner benchmark completed;
- synthetic 1,000-file integrity benchmark completed.

## Native status

**Windows v0.6.1 hardening acceptance pending.** The previously frozen v0.6.0-beta.3 remains the last natively accepted baseline until the new live hardening + reboot gates pass.

## Boundary

This is user-mode tamper resistance, not PPL/kernel anti-tamper. Keep Microsoft Defender enabled. Do not test with real malware on an everyday machine.
