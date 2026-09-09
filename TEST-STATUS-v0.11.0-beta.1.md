# TEST STATUS — BC Sentinel v0.11.0-beta.1

## Current state
**WINDOWS FUNCTIONAL ACCEPTANCE PASS / SERVICE PERFORMANCE FIX IMPLEMENTED / THREAT-PACKAGE WINDOWS PUBLISH FIX IMPLEMENTED / NATIVE RETEST REQUIRED**

### Functional Windows evidence — 2026-09-09
A complete one-command Windows run previously reached the final functional PASS marker before the service-performance defect was promoted to a hard gate.

Observed evidence:
- **563 pytest tests passed, 0 failed**;
- v0.11 EDR local and post-admin acceptance: PASS;
- telemetry persistence, process tree, query surface, deduplication, flood guard and restart persistence: PASS;
- HIGH multi-signal incident with deterministic + execution evidence: PASS;
- v0.10 Beta1/Beta2/Beta3/RC1 regressions: PASS;
- Protection Service + UAC Broker PyInstaller builds: PASS;
- named-pipe self-test: PASS;
- automatic UAC/admin orchestration: PASS;
- upgrade/same-version anti-downgrade + real repair path: PASS;
- standard-user direct gate correctly required elevation;
- broker issued/consumed/completed: 1/1/1, rejected: 0;
- service health: `HEALTHY`;
- hardening: `sealed`;
- authenticated integrity manifest, HMAC config, ACL and SCM checks: PASS;
- reboot remains explicitly deferred to final-roadmap validation.

## Performance defect discovered after the functional PASS
Generated Windows benchmark `benchmark-v011-beta1-service.json` reported:

- service PID: `5548`;
- RSS idle: `194,719,744` bytes;
- **idle CPU: 116.55% of one core** over 5 seconds;
- IPC: `200/200`, `31.1 req/s`;
- benign event storm: `500` files / `1500` operations, `154.68%` of one core;
- hardening: healthy/sealed.

The old benchmark returned `passed=true` because it checked only IPC completion and hardening posture. That result is now considered a **false performance PASS**. v0.11.0-beta.1 is not frozen or merge-ready with 116.55% idle CPU.

## Performance fix implemented
The branch now adds:

1. **Kernel-File ETW early filtering**
   - keeps path-bearing events used by the existing correlation pipeline: Create (12), DeletePath (26), RenamePath (27), CreateNewFile (30);
   - avoids fully decoding high-volume Read/Write/Cleanup/QueryInfo/FSCTL families that do not provide a usable path to the current monitor.

2. **Bounded microburst deduplication**
   - identical PID/path/task/event-id file events inside a 350 ms window are suppressed;
   - cache is bounded and time-pruned.

3. **Fail-closed service performance benchmark**
   - idle CPU must be `<= 25%` of one core;
   - IPC throughput must be `>= 10 req/s` and all requests must succeed;
   - benign event-storm CPU must be `<= 250%` of one core;
   - hardening must remain healthy;
   - result includes checks, thresholds and failure reasons.

4. **One-command visibility**
   - the normal launcher deletes any stale service benchmark before UAC;
   - after the elevated phase it reads and prints the current idle/IPC/storm metrics itself;
   - `ALL GATES PASS` is impossible when the enforced service-performance benchmark fails.

5. **Regression coverage**
   - the exact observed `116.55%` idle case is encoded as a required benchmark failure;
   - ETW provider filtering and duplicate-window behavior are covered by deterministic tests.

### Local verification of the performance patch
On the complete RC1 source tree used for development:

- targeted ETW/Web/service-performance suite: **47 passed**;
- complete local suite after patch: **551 passed, 2 Windows-only skipped**;
- `compileall`: PASS.

These local results validate the patch structure but do not prove Windows CPU reduction.

## Latest Windows retest blocker — threat-package atomic publish
The next Windows run progressed through dependency preparation and reached:

- **566 pytest passed**;
- **1 pytest failed**;
- failure: `test_v010_beta1_acceptance_records_deferred_v090_native_gates`;
- root exception: `PermissionError [WinError 5]` while atomically replacing `active-behavior.json.tmp -> active-behavior.json` during the v0.8 last-known-good threat-package rollback fixture.

The failure occurred before the admin/performance phase, so it does not provide new CPU evidence and does not invalidate the already-green EDR logic.

## Threat-package Windows publish fix implemented
The v0.11 overlay now applies a guarded, fail-closed compatibility migration to the complete FULL baseline before pytest:

- managed JSON publication uses a bounded atomic-file replace retry helper;
- retries are limited to Windows transient access/share/lock conditions `WinError 5`, `32`, `33`;
- unrelated errors are raised immediately;
- after the bounded retry budget is exhausted the operation fails closed with `ThreatPackageError`;
- YARA directory promotion semantics are left unchanged;
- state, activation journal and active behavior JSON publication use the hardened helper;
- the source-shape migration verifies exact anchors and refuses unexpected source variants.

Regression coverage added:
- transient WinError 5 succeeds after bounded retries;
- persistent WinError 32 fails closed;
- unrelated OSError is not retried.

Fresh RC1 reproduction of this compatibility fix:
- migration applied successfully;
- threat-package + v0.8 signed-intelligence + v0.10 Web regression subset: **27 passed**.

## Required native retest before Beta1 acceptance
Synchronize the latest `v0.11.0-beta.1` branch over the complete FULL tree and run only the official one-command launcher:

```powershell
.\TEST-V011-BETA1-ALL.bat
```

Beta1 may be accepted only if both the new threat-package regression and the enforced performance outcome pass:

```text
full pytest = PASS
threat-package atomic publish regression = PASS
idle <= 25.00% of one core
IPC >= 10.00 requests/s with all requests successful
storm <= 250.00% of one core
service benchmark passed = true
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

If either the atomic publish or idle CPU remains unhealthy, the launcher must fail before v0.11.0-beta.2.

### Deferred
`REBOOT PERSISTENCE GATE: DEFERRED TO FINAL ROADMAP VALIDATION`

## GitHub caveat
The connected repository's v0.10 RC1 branch is still smaller than the FULL Windows package used for native acceptance. The v0.11 branch is an overlay/delta until that baseline is synchronized; the launcher intentionally fails preflight when required FULL files are absent.
