# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**FUNCTIONAL/NATIVE GATES GREEN THROUGH SERVICE PERFORMANCE / IDLE CPU BLOCKER REMAINS / PYWINTRACE IDLE-SPIN FIX IMPLEMENTED**

### Latest Windows evidence — 2026-09-09
The newest one-command Windows run confirms:

- dependency preparation: PASS;
- legacy regression compatibility: canonical;
- threat-package Windows compatibility: canonical;
- service-update Windows compatibility: canonical;
- split Process/File/DNS ETW compatibility with provider-side Event ID filters: PASS;
- **577 pytest passed, 0 failed**;
- v0.11 EDR local acceptance: PASS;
- v0.10 Beta1/Beta2/Beta3/RC1 local regressions: PASS;
- Protection Service + UAC Broker + firewall build: PASS;
- named-pipe self-test: PASS;
- automatic UAC/admin phase progressed through functional/live gates and reached `service_performance`.

The enforced benchmark correctly failed only on idle CPU:

```text
ADMIN PHASE RESULT: status=FAIL | stage=service_performance | message=Service hardening/performance benchmark failed
SERVICE PERFORMANCE: idle=149.68% one-core | IPC=27.76/s | storm=158.46% one-core | passed=False
idle CPU 149.68% exceeds 25.00% of one core
BC SENTINEL v0.11.0-beta.1 - ALL GATES FAIL
```

IPC and benign-storm metrics are healthy. Idle CPU remains the only current performance blocker.

## What the latest result disproved
Moving Event ID filtering from the Python consumer to the ETW provider changed idle CPU only marginally (`152.18% -> 149.68%`). Therefore high idle CPU is not primarily caused by excess event volume.

The next dominant suspect is the `pywintrace 0.2.0` consumer loop. Its `EventConsumer._run()` repeatedly calls `ProcessTrace()` in a `while True`; if a real-time `ProcessTrace()` call returns `SUCCESS` almost immediately on this Windows build, the consumer immediately re-enters it with no wait. Three active ETW sessions can therefore produce sustained idle spin even when event filtering is correct.

## Low-CPU consumer compatibility fix implemented
The branch now includes `sentinel/pywintrace_idle.py` and injects it before ETW sessions are created.

Behavior:

- normal blocking `ProcessTrace()` behavior is unchanged;
- if `ProcessTrace()` returns successfully in <= 5 ms while capture is still active, the consumer performs a bounded interruptible 10 ms `Event.wait()` before re-entering;
- errors remain fail-closed and terminate that consumer loop;
- shutdown remains responsive because the backoff waits on the existing stop event rather than using an unconditional sleep;
- no dependency upgrade, cloud service, telemetry removal, or lowered security gate is introduced.

The normal compatibility migrator installs/verifies the hook before pytest/build and the regression suite requires it.

## Additional benchmark diagnostics
`tools/service_hardening_benchmark.py` now records per-thread idle CPU deltas (`idle.hottest_threads`) and service thread count. If total idle CPU remains excessive after the backoff, the same benchmark JSON will identify the hottest Windows thread IDs instead of requiring another blind diagnostic round.

## ETW architecture retained
The three independent sessions and provider-side filters remain:

- Process: event IDs `1, 2`;
- Kernel-File: `12, 26, 27, 30`;
- DNS: `3006, 3008, 3018, 3020`.

Consumer-side filters remain as defense in depth and DNS startup retry remains bounded.

## Performance acceptance thresholds
The benchmark remains fail-closed and unchanged:

```text
idle <= 25.00% of one core
IPC >= 10.00 requests/s with all requests successful
storm <= 250.00% of one core
hardening healthy
```

The idle threshold is not relaxed.

## Required Beta1 retest
Synchronize latest `v0.11.0-beta.1` over the authoritative FULL Windows tree and run only:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Required final evidence:

```text
full pytest = PASS
ADMIN PHASE RESULT: status=PASS | stage=completed
SERVICE PERFORMANCE: idle<=25% one-core | IPC>=10/s | storm<=250% one-core | passed=True
REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

If idle remains above threshold, inspect `benchmark-v011-beta1-service.json -> idle.hottest_threads` and fix the identified hot path before Beta1 freeze.

v0.11.0-beta.1 remains **not frozen / not merge-ready** until the native performance gate is green.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is smaller than the complete FULL Windows package used for native acceptance. The v0.11 branch remains an overlay/delta until that baseline is synchronized; the launcher intentionally fails preflight when required FULL files are absent.
