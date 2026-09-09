# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**DEVELOPMENT / WINDOWS RETEST REQUIRED**

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
The latest complete Windows run reached:
- **561 pytest tests passed, 0 failed**;
- legacy v0.7 contaminated ROADMAP regression canonicalization: PASS;
- EDR acceptance then stopped during temporary-directory cleanup with Windows `WinError 32` because `edr.sqlite3` remained locked;
- this was isolated to SQLite connection lifecycle/cleanup, not detection logic or the full regression suite.

The source fix now makes every `EdrTelemetryStore` connection explicitly close after commit/rollback, adds direct lifecycle regression tests, and makes the acceptance harness cleanup deterministic. A Windows retest is required before Beta1 can be accepted.

### Prior baseline evidence
The v0.10.0-rc.1 FULL Windows package was reported with:
- 549 pytest tests passed in the normal suite;
- Beta1/Beta2/Beta3/RC1 local acceptances passed;
- standard-user → UAC broker acceptance passed;
- the one-command orchestrator completed with `ALL NORMAL-ORCHESTRATED TESTS PASS`;
- reboot explicitly deferred.

This evidence belongs to v0.10.0-rc.1 and is **not automatically transferred** to v0.11.0-beta.1.

### Required before accepting Beta1
Run from the complete v0.10 RC1 FULL source tree after applying/synchronizing the latest v0.11 branch:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Required result:

```text
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

The launcher must prove:
- complete regression suite;
- v0.11 EDR tests + acceptance;
- native Authenticode/ETW/firewall/service gates;
- Protection Service/UAC Broker build;
- real upgrade or same-version anti-downgrade path;
- real repair;
- Windows/service hardening benchmarks;
- standard-user → UAC Broker;
- zero critical failures.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is still smaller than the FULL Windows package. The v0.11 launcher intentionally fails preflight when those required baseline files are absent rather than producing a false PASS.
