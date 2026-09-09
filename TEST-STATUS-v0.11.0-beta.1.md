# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**FUNCTIONAL/NATIVE GATES REACH SERVICE PERFORMANCE / IDLE CPU BLOCKER REMAINS / PROVIDER-SIDE ETW FIX IMPLEMENTED**

### Latest Windows evidence — 2026-09-09
The newest one-command Windows run reached the enforced service-performance gate:

- dependency preparation: PASS;
- legacy regression compatibility: canonical;
- threat-package Windows compatibility: canonical;
- service-update Windows compatibility: canonical;
- split Process/File/DNS ETW compatibility: PASS;
- **577 pytest passed, 0 failed**;
- v0.11 EDR local acceptance: PASS;
- EDR throughput: `84.88 events/s` vs `50/s` minimum;
- v0.10 Beta1/Beta2/Beta3/RC1 local regressions: PASS;
- compatibility matrix: `323/323`, 0 failures;
- Protection Service + UAC Broker + firewall build: PASS;
- named-pipe self-test: PASS;
- automatic UAC/admin phase progressed through functional/live gates and reached `service_performance`.

The enforced benchmark then correctly failed:

```text
ADMIN PHASE RESULT: status=FAIL | stage=service_performance | message=Service hardening/performance benchmark failed
SERVICE PERFORMANCE: idle=152.18% one-core | IPC=33.49/s | storm=172.01% one-core | passed=False
idle CPU 152.18% exceeds 25.00% of one core
BC SENTINEL v0.11.0-beta.1 - ALL GATES FAIL
```

This is a valid fail-closed result. IPC and benign-storm metrics are within their limits; **idle CPU is the only current performance blocker**.

## Root cause and performance fix now implemented
The previous `event_id_filters` optimization was consumer-side in `pywintrace`: unwanted events were still delivered by ETW to the Python process and only discarded inside the consumer callback path. This preserved correctness but did not remove the dominant idle event-processing cost.

The branch now uses **provider-side ETW Event ID filters** through `ProviderParameters` / `EVENT_FILTER_EVENT_ID`, passed to `EnableTraceEx2` before events reach the Python consumer.

The three independent sessions are preserved and narrowed to the telemetry actually consumed by BC Sentinel:

- Process provider: event IDs `1, 2` only — ProcessStart / ProcessStop;
- Kernel-File provider: event IDs `12, 26, 27, 30` only — path-bearing file families used by correlation;
- DNS provider: event IDs `3006, 3008, 3018, 3020` only — query/response/cache telemetry used by Web/EDR correlation.

Consumer-side `event_id_filters` remain as defense in depth. Provider-filter ctypes objects are explicitly kept alive for the full capture lifetime. No new dependency or cloud service is introduced; pinned `pywintrace==0.2.0` remains supported.

The compatibility verifier and regression suite now require:

- `ETW_PROVIDER_FILTER_MODE = "provider_side_event_id_v2"`;
- `EVENT_FILTER_EVENT_ID` + `ProviderParameters` provider filtering;
- all three session-specific Event ID sets;
- no unsupported `providers_event_id_filters` constructor argument;
- split Process/File/DNS architecture and bounded DNS retry.

## Performance acceptance thresholds
The benchmark remains unchanged and fail-closed:

```text
idle <= 25.00% of one core
IPC >= 10.00 requests/s with all requests successful
storm <= 250.00% of one core
hardening healthy
```

The threshold is **not** being relaxed to accommodate the current result.

## Required Beta1 retest
Synchronize the latest `v0.11.0-beta.1` overlay onto the authoritative FULL Windows tree and run only:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Required final parent-console evidence:

```text
full pytest = PASS
ADMIN PHASE RESULT: status=PASS | stage=completed | message=Administrator phase completed successfully
SERVICE PERFORMANCE: idle<=25% one-core | IPC>=10/s | storm<=250% one-core | passed=True
REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

v0.11.0-beta.1 remains **not frozen / not merge-ready** until that native performance result is green.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is smaller than the complete FULL Windows package used for native acceptance. The v0.11 branch remains an overlay/delta until that baseline is synchronized; the launcher intentionally fails preflight when required FULL files are absent.