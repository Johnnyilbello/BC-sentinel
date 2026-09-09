# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**LOCAL/FUNCTIONAL WINDOWS SUITE GREEN / ELEVATED PHASE DIAGNOSTICS IMPROVED / FINAL NATIVE+PERFORMANCE RETEST REQUIRED**

### Latest Windows evidence — 2026-09-09
The newest one-command Windows run confirms the previously failing local regression path is now green:

- dependency preparation: PASS;
- legacy regression compatibility: canonical;
- threat-package Windows compatibility migration: applied;
- **570 pytest passed, 0 failed**;
- v0.11 EDR local acceptance: PASS;
- telemetry persistence: PASS;
- process tree: PASS;
- download/execution/network/persistence correlation: PASS;
- HIGH multi-signal incident: PASS;
- deterministic evidence: PASS;
- incident persistence across restart: PASS;
- stable event deduplication: PASS;
- flood guard: PASS;
- query surface: PASS;
- EDR throughput floor: PASS;
- v0.10 Beta1/Beta2/Beta3/RC1 local regressions: PASS;
- Protection Service + UAC Broker + firewall build: PASS.

The run then entered the automatic UAC administrator phase but returned only:

```text
BC SENTINEL v0.11.0-beta.1 - ALL GATES FAIL
Automated administrator phase failed with exit code 1
```

The parent console did not expose the failing elevated gate, so this run does **not** provide valid new evidence for upgrade/repair/live Windows acceptance or the enforced service-performance benchmark.

## Elevated-phase diagnostics fix implemented
The branch now persists an administrator-phase result to:

```text
acceptance-v011-beta1-admin-phase-result.json
```

The elevated script records:

- `status` (`PASS`/`FAIL`);
- exact `stage`;
- failure/success `message`;
- timestamp.

Tracked stages include:

- `targeted_tests`;
- `build_preflight`;
- `service_install_preflight`;
- `upgrade`;
- `repair`;
- `live_regressions`;
- `edr_admin_acceptance`;
- `windows_acceptance`;
- `service_performance`;
- `completed`.

The normal launcher removes stale admin/benchmark artifacts before UAC, reads the new result after the elevated process exits, prints the exact stage/message in the parent console, and refuses to accept a missing/unreadable admin result.

## Previously discovered performance blocker
A prior Windows benchmark reported:

- idle CPU: **116.55% of one core** over 5 seconds;
- IPC: `200/200`, `31.1 req/s`;
- benign event storm: `154.68%` of one core;
- hardening: healthy/sealed.

That legacy `passed=true` was a false performance PASS because CPU was not part of the pass criteria.

The current benchmark is fail-closed and requires:

```text
idle <= 25.00% of one core
IPC >= 10.00 requests/s with all requests successful
storm <= 250.00% of one core
hardening healthy
```

The normal launcher also prints the current idle/IPC/storm measurements and cannot reach `ALL GATES PASS` if the benchmark fails.

## Performance and Windows compatibility fixes already implemented
- Kernel-File ETW early filtering to path-bearing event families currently usable by the correlation pipeline;
- bounded 350 ms PID/path/task/event microburst deduplication;
- fail-closed service-performance benchmark with explicit thresholds and failure reasons;
- regression encoding the old 116.55% idle result as a required failure;
- bounded atomic-file replace retries for transient Windows WinError 5/32/33 during threat-package JSON publication;
- fail-closed behavior after retry exhaustion;
- regression coverage for transient/persistent/unrelated replace failures.

## Required final Beta1 retest
Synchronize latest `v0.11.0-beta.1` over the complete FULL Windows tree and run only the official launcher:

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

If the elevated process fails, the parent console must now show the exact failing stage and message instead of only `exit code 1`.

v0.11.0-beta.1 remains **not frozen / not merge-ready** until this final native retest is green.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is smaller than the complete FULL Windows package used for native acceptance. The v0.11 branch remains an overlay/delta until that baseline is synchronized; the launcher intentionally fails preflight when required FULL files are absent.
