# BC Sentinel v0.11.0-beta.1 — EDR Telemetry & Detection Foundation

## Scope
This milestone starts the v0.11 EDR line on top of the v0.10.0-rc.1 Web Protection consolidation baseline.

### Added
- persistent local SQLite EDR telemetry;
- stable `BCE-*` event identifiers and duplicate suppression;
- process PID/PPID tree reconstruction;
- process/file/DNS-network/download/persistence timeline fields;
- local query filters by PID, category and time;
- bounded retention and maximum event storage;
- per-PID/category flood guard;
- multi-signal EDR correlation with stable `BCEDR-*` incidents;
- browser → download → interpreter/LOLBin → IOC chain correlation;
- deterministic signed-IOC/file-verdict evidence support;
- persisted incidents and restart recovery;
- explainable evidence families, signal codes, score and confidence;
- acceptance harness and deterministic tests;
- one-command Windows test launcher that elevates its own admin phase via UAC.

## Safety invariants
- one heuristic family cannot qualify HIGH;
- no automatic process kill;
- no automatic file deletion;
- no automatic host isolation;
- no mandatory cloud dependency;
- no HTTPS MITM/decryption introduced;
- existing v0.10 reversible web-response and shared-IP/CDN safeguards remain regression requirements.

## Windows orchestration
Official command from a normal PowerShell:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

The launcher prepares `.venv`, installs requirements, runs the complete pytest suite, EDR acceptance and v0.10 regressions, opens the elevated phase itself, performs native/service tests plus upgrade/repair, returns to standard-user UAC acceptance, and reports one final PASS/FAIL.

Reboot persistence remains deliberately deferred to the final roadmap validation.

## Source synchronization warning
The GitHub `v0.10.0-rc.1` branch is not yet the complete Windows tree that produced the 549-test local RC1 evidence. `TEST-V011-BETA1-ALL.ps1` therefore contains a FULL-baseline preflight and refuses to present a delta-only checkout as a complete release package.

`v0.11.0-beta.1` is a development branch until the complete RC1 source tree is synchronized and the new Windows suite is executed on that FULL tree.
