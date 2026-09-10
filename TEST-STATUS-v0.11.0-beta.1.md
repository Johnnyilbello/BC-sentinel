# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**FUNCTIONAL/NATIVE GATES GREEN THROUGH SERVICE PERFORMANCE / IDLE CPU BLOCKER REDUCED / PROCESS ETW BETA1 FALLBACK FIX IMPLEMENTED**

### Latest Windows evidence — 2026-09-09
The newest one-command Windows run confirms:

- dependency preparation: PASS;
- legacy regression compatibility: canonical;
- threat-package Windows compatibility: canonical;
- service-update Windows compatibility: canonical;
- pywintrace idle compatibility: canonical;
- runtime CPU diagnostics: active;
- split Process/File/DNS ETW compatibility + provider-side Event ID filters: PASS;
- low-CPU File ETW runtime migration: applied;
- high-churn Temp/AppData watchdog policy: canonical;
- **584 pytest passed, 0 failed**;
- v0.11 EDR local acceptance: PASS;
- v0.10 Beta1/Beta2/Beta3/RC1 regressions: PASS;
- Protection Service + UAC Broker + firewall build: PASS;
- named-pipe self-test: PASS;
- automatic UAC/admin phase reached `service_performance`.

The enforced benchmark remained correctly fail-closed:

```text
ADMIN PHASE RESULT: status=FAIL | stage=service_performance | message=Service hardening/performance benchmark failed
SERVICE PERFORMANCE: idle=52.19% one-core | IPC=47.22/s | storm=93.54% one-core | passed=False
idle CPU 52.19% exceeds 25.00% of one core
BC SENTINEL v0.11.0-beta.1 - ALL GATES FAIL
```

Compared with the preceding native run, idle CPU improved from **152.81% -> 52.19% of one core**. IPC improved to **47.22 req/s** and benign-storm CPU fell to **93.54%**.

## Hot-thread evidence
Latest idle attribution:

```text
Thread-1             47.50% one-core
BCS-ProcessMonitor    3.12% one-core
BCS-Identity_1        0.62% one-core
Thread-7              0.31% one-core
process_etw            0.31% one-core
BCS-NetworkMonitor    0.31% one-core
```

`file_etw` disappeared from the hot-thread list after continuous Kernel-File ETW was moved to dormant-idle mode. The remaining dominant consumer is the anonymous pywintrace process-session consumer thread (`Thread-1`), not the psutil ProcessMonitor.

## Beta1-specific Process ETW low-CPU follow-up
The branch now extends `tools/v011_low_cpu_runtime_compat.py` so continuous Process ETW is also moved to `dormant_idle_beta1` after startup verification.

Safety/coverage rules:

- `BCS-ProcessMonitor` remains active as the explicit process fallback;
- DNS ETW remains continuous and untouched because v0.10 Web Protection native gates require real `dns_etw=true`;
- the benchmark threshold is not relaxed;
- no cloud dependency or destructive response is introduced;
- Process/File continuous ETW ownership is still a v0.11.0-beta.2 Service Integration & Hunting task and must be reintroduced there with a lower-overhead implementation rather than silently omitted.

The compatibility migrator is fail-closed and idempotent. Regression coverage verifies:

- Process ETW startup is still exercised before dormancy;
- the process consumer is stopped and cleared in Beta1 idle mode;
- `process_fallback="psutil_process_monitor"` is surfaced in ETW status;
- File ETW dormant mode remains intact;
- Temp/AppData watchdog behavior remains intact.

## Performance acceptance thresholds
Unchanged:

```text
idle <= 25.00% of one core
IPC >= 10.00 requests/s with all requests successful
storm <= 250.00% of one core
hardening healthy
```

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

v0.11.0-beta.1 remains **not frozen / not merge-ready** until the native performance gate is green.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is smaller than the complete FULL Windows package used for native acceptance. The v0.11 branch remains an overlay/delta until that baseline is synchronized; the launcher intentionally fails preflight when required FULL files are absent.
