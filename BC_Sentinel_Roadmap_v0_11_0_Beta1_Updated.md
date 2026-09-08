# BC Sentinel — Roadmap checkpoint v0.11.0-beta.1

## Baseline
Development advances from **v0.10.0-rc.1 Web Protection Consolidation** to **v0.11.0-beta.1 EDR Telemetry & Detection Foundation**.

The v0.10 RC1 FULL Windows run is the operational baseline for this milestone. Reboot persistence is still deferred to the final roadmap validation and older v0.9 native-freeze flags are not retroactively rewritten.

## v0.11 EDR plan

### v0.11.0-beta.1 — Telemetry & Detection Foundation — current
- durable local telemetry timeline;
- process PID/PPID graph;
- process/file/network/DNS/download/persistence event model;
- stable event IDs and deduplication;
- local query surface;
- retention and flood protection;
- explainable multi-signal correlation;
- persistent `BCEDR-*` incidents;
- deterministic IOC/file-verdict evidence;
- no single-heuristic HIGH;
- no automatic kill/delete/isolation;
- no mandatory cloud;
- one-command Windows acceptance orchestration.

### Planned v0.11.0-beta.2 — Service Integration & Hunting
- Protection Service owns the EDR telemetry store;
- native ETW/process/network/file events feed the EDR pipeline continuously;
- authenticated IPC query endpoints for timeline/process tree/incidents;
- IOC retrospective hunting across persisted events;
- bounded pagination and retention administration;
- Security Center Inbox integration for qualified EDR incidents;
- no autonomous destructive response.

### Planned v0.11.0-beta.3 — Root Cause & Reversible Containment
- incident root-cause/process-tree view;
- deterministic containment qualification;
- reversible network/host containment behind explicit protected/UAC workflows;
- lease/TTL, audit and rollback;
- false-positive and shared-infrastructure safeguards;
- no heuristic-only host isolation.

### Planned v0.11.0-rc.1 — EDR Consolidation
- Beta1→Beta3 regression freeze;
- benign enterprise process-tree matrix;
- event-storm and retention stress tests;
- service restart/recovery and datastore corruption handling;
- native Windows live evidence for every advertised EDR function;
- no production acceptance until all required native gates are green.

## Current Beta1 acceptance rule
Do not mark v0.11.0-beta.1 accepted until the complete v0.10 RC1 FULL source tree has the v0.11 changes applied and this command finishes green on Windows:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Required final line:

```text
BC SENTINEL v0.11.0-beta.1 — ALL GATES PASS
```

Reboot remains explicitly deferred.
