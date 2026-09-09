# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**WINDOWS FUNCTIONAL ACCEPTANCE PASS / FINAL SERVICE-IDLE CPU EVIDENCE PENDING**

### Implemented in source
- EDR persistent telemetry store;
- event deduplication;
- process tree;
- multi-signal correlation;
- persistent incidents;
- retention and flood guard;
- local query surface;
- EDR acceptance harness;
- deterministic unit tests;
- explicit SQLite connection lifecycle with commit/rollback + guaranteed close;
- regression tests for closed SQLite handles/removable DB files;
- deterministic acceptance cleanup on Windows;
- one-command Normal → automatic UAC/Admin → standard-user UAC orchestration.

### Windows evidence — 2026-09-09
The latest complete one-command Windows run reached the final PASS marker.

Observed evidence:
- **563 pytest tests passed, 0 failed**;
- legacy regression compatibility: already canonical;
- v0.11 EDR local acceptance: PASS;
- telemetry persistence: PASS;
- process tree: PASS;
- download correlation: PASS;
- HIGH multi-signal incident: PASS;
- deterministic + execution evidence: PASS;
- incident persistence across store restart: PASS;
- stable event deduplication: PASS;
- flood guard: PASS;
- local EDR query surface: PASS;
- EDR throughput floor: PASS (observed ~74–82 events/s in Windows runs, minimum 50/s);
- v0.10 Beta1/Beta2/Beta3/RC1 regressions: PASS;
- Protection Service + UAC Broker PyInstaller builds: PASS;
- named-pipe self-test: PASS;
- firewall/native build gate: PASS;
- automatic UAC/admin orchestration: PASS;
- standard-user direct gate correctly required elevation;
- broker issued/consumed/completed: 1/1/1, rejected: 0;
- post-admin health: HEALTHY;
- hardening mode: sealed;
- authenticated integrity manifest: PASS;
- HMAC config verification: PASS;
- install/data/integrity-key ACL checks: PASS;
- SCM service configuration: PASS;
- EDR post-admin acceptance: PASS;
- launcher final marker: `BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS`;
- reboot persistence remains explicitly deferred to final-roadmap validation.

### Remaining acceptance evidence before merge/freeze
The admin phase executes `tools.service_hardening_benchmark`, and the launcher returned success, but the parent console log does not contain the benchmark's detailed CPU-idle measurements because that output is emitted in the elevated process window.

This matters because an earlier v0.10/Beta3 service benchmark reported very high idle CPU while still returning `passed=true`. Therefore v0.11 Beta1 is not frozen/merged until the generated `benchmark-v011-beta1-service.json` is inspected and the Protection Service idle CPU is confirmed reasonable (or fixed if still excessive).

No functional/security regression is currently open from the latest run.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is still smaller than the FULL Windows package used for native acceptance. The v0.11 launcher intentionally fails preflight when required FULL baseline files are absent rather than producing a false PASS.
