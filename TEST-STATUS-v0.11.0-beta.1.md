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
- one-command Normal → automatic UAC/Admin → standard-user UAC orchestration.

### Prior baseline evidence
The v0.10.0-rc.1 FULL Windows package was reported with:
- 549 pytest tests passed in the normal suite;
- Beta1/Beta2/Beta3/RC1 local acceptances passed;
- standard-user → UAC broker acceptance passed;
- the one-command orchestrator completed with `ALL NORMAL-ORCHESTRATED TESTS PASS`;
- reboot explicitly deferred.

This evidence belongs to v0.10.0-rc.1 and is **not automatically transferred** to v0.11.0-beta.1.

### Required before accepting Beta1
Run from the complete v0.10 RC1 FULL source tree after applying/synchronizing the v0.11 branch:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Required result:

```text
BC SENTINEL v0.11.0-beta.1 — ALL GATES PASS
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
