# BC Sentinel v0.6.0 Beta — Protection Service Engineering Report

## A. Baseline

Baseline: BC Sentinel v0.5.0 Beta — Incident Correlation & Response.

User-supplied Windows 11 acceptance before this phase:

- Python 3.12.10;
- administrator context;
- 176 tests PASS;
- target platform PASS;
- watchdog native Observer PASS;
- ETW process/file PASS;
- Authenticode PASS;
- process→network attribution PASS;
- Behavioral Correlation Engine v2 PASS;
- Incident Response Foundation PASS;
- no critical failures.

The v0.5 architecture still launched major protection monitors inside the GUI and used a localhost TCP telemetry service protected primarily by a shared local secret.

## B. Architecture

v0.6 target:

```text
Standard-user PySide6 GUI
        |
Windows Named Pipe + ACL
strict JSON protocol + install token
client Windows identity / admin gate
        |
BCSentinelProtection Windows Service
        |
Realtime / Process / ETW / Persistence / Network
Behavioral Correlation / Incidents / Response
ProgramData service state + audit + quarantine
```

When the service reports `HEALTHY` or `DEGRADED` with protection enabled, the GUI does not start duplicate realtime/process/persistence/network collectors. If the service disappears, deterministic local user-space fallback is started according to user settings.

## C. Service Implementation

Implemented `BCSentinelProtection` using pywin32 `ServiceFramework`.

Lifecycle:

- install/remove via `INSTALLA-SERVIZIO-PROTEZIONE.ps1`;
- automatic startup;
- graceful stop path;
- service-owned runtime start/stop;
- named-pipe listener lifecycle;
- global duplicate-engine guard;
- conservative SCM recovery policy: delayed restart attempts rather than rapid infinite restart loops.

Service state is under `%PROGRAMDATA%\BCSentinel\Protection`.

Long-running ownership moved to the service for:

- realtime filesystem scanning/ransomware events;
- process monitoring;
- ETW process/file telemetry;
- persistence monitoring;
- network monitoring/reputation enrichment;
- Behavioral Correlation Engine 2.0;
- incident creation/persistence;
- guarded response authority.

## D. IPC Security

The old v0.5 localhost TCP broker is no longer used by the v0.6 protection path.

Production IPC uses Windows Named Pipes:

`\\.\pipe\BCSentinelProtection-v1`

Controls:

- pipe security descriptor / ACL;
- local Windows client impersonation;
- SID extraction;
- administrator-membership check for privileged operations;
- per-installation secret verification using constant-time comparison;
- protocol version;
- request ID;
- explicit operation allowlist;
- per-operation payload schemas;
- strict primitive types/ranges;
- path length/NUL validation;
- 256 KiB maximum message size;
- malformed UTF-8/JSON rejection;
- unknown field/operation rejection;
- deterministic JSON responses;
- privileged-action audit records.

No pickle, Python object deserialization, generic method invocation, shell API or arbitrary command RPC is exposed.

### Authorization classes

Read operations require a local client plus valid install token.

Privileged mutations additionally require a transport-authenticated Windows administrator identity. Examples include:

- protection/network configuration changes;
- disable/enable protection;
- process termination;
- file quarantine;
- quarantine restore;
- exclusion mutation.

This intentionally fails closed for a standard-user GUI. A dedicated one-action elevated broker is deferred to v0.6.1 rather than weakening the service policy.

## E. Least Privilege

The GUI no longer needs to own privileged ETW/service protection when `BCSentinelProtection` is active.

The service is intended to run with the privileges required for machine protection; the PySide6 GUI may run normally at standard-user integrity for status/telemetry/use.

Current limitation: privileged UI mutations require an elevated client context. v0.6 does not yet provide a polished per-action UAC helper, so a standard GUI receives `admin_required` rather than bypassing the service or performing the operation locally.

## F. Self-Protection Foundation

Implemented user-space foundations:

- ProgramData service-state separation;
- installer ACL hardening;
- service configuration stored separately from GUI settings;
- atomic config write/replace;
- HMAC integrity verification before service consumption;
- reparse-point rejection for service config/secret paths;
- dedicated service quarantine path/key;
- privileged-action JSONL audit;
- cross-process duplicate-engine mutex/lock.

These are **not kernel-grade tamper protection**. A sufficiently privileged administrator/SYSTEM attacker remains outside the guarantees of this phase.

## G. Tests

Baseline before v0.6 modification: `176/176 PASS`.

Added 21 focused v0.6 tests covering:

- strict JSON roundtrip;
- malformed JSON;
- unsupported protocol version;
- unknown operations/fields;
- oversized messages;
- pickle bytes rejected as non-JSON;
- read-only standard-user operation;
- authenticated-transport requirement;
- administrator gate;
- bad install token;
- remote context rejection;
- config tamper detection;
- atomic config update;
- health degradation semantics;
- no TCP/pickle management surface;
- named-pipe impersonation/ACL source contract;
- no arbitrary command API;
- GUI duplicate-engine prevention.

Final development result: **197/197 tests PASS**.

`python -m compileall -q sentinel app tools packaging`: PASS.

## H. Performance

The scanner algorithm was not intentionally changed in v0.6; this phase focuses on lifecycle, IPC and privilege boundaries.

User-supplied v0.5 native Windows 5,000-file baseline before v0.6:

- cold: 104.869 s / 47.68 files/s;
- warm: 89.779 s / 55.69 files/s;
- warm hash-cache hits: 4,950;
- realtime observer: ~20.22% of one core during the 3-second acceptance probe;
- realtime RSS end: ~53.9 MB.

A v0.6 native Windows benchmark must be rerun after installing the actual Protection Service. Linux/container timings are not used to claim Windows service performance.

## I. Known Limitations

- No kernel minifilter/WFP.
- No kernel anti-tamper.
- No autonomous destructive heuristic response.
- No polished per-action UAC broker yet.
- The service-account HKCU view does not equal complete multi-user persistence coverage; this is a v0.6.1 target.
- Service-owned quarantine permanent deletion is intentionally not exposed through IPC yet.
- Service and GUI maintain separate persistent databases; service event IDs are propagated so the UI presentation database can preserve canonical incident identity.
- Configuration changes affecting monitor topology are persisted safely but generally require a service restart for complete application, except the explicit network toggle.
- Native named-pipe/service behavior cannot be certified from the Linux development container.

## J. Next Phase

Recommended next release: **v0.6.1 — Protection Service Hardening & Tamper Resistance**.

Priorities:

1. dedicated elevated one-action broker so privileged commands work without elevating the entire GUI;
2. service-SID/resource ACL ownership hardening;
3. multi-user persistence coverage;
4. adversarial named-pipe fuzzing/client impersonation tests;
5. service crash/recovery/upgrade testing;
6. last-known-good configuration rollback;
7. stronger tamper detection and evaluation of Rust/C++ for security-critical boundaries.

### Development-container scanner sanity benchmark

A non-Windows 5,000-file sanity run was also executed only to detect accidental scanner regressions:

- cold: 2.167 s / 2,307.75 files/s;
- warm: 1.724 s / 2,899.86 files/s;
- warm hash-cache hits: 4,950/5,000;
- native watchdog unavailable in this container, so realtime used `direct_pipeline_fallback`.

These figures are **not** a substitute for the Windows service-live acceptance benchmark.

## v0.6.0-beta.3 field hardening
- Client identity now falls back from Named Pipe impersonation to kernel-reported client PID/process token.
- Production pipe rejects remote clients.
- Native service-live acceptance remains required before freeze.
