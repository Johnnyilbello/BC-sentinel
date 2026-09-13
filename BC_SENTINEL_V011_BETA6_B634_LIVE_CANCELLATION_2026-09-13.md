# BC Sentinel v0.11.0-beta.6 — B6-3.4 Live Cancellation Acceptance

Date: 2026-09-13

Branch: `feature/v011-beta6-b63-smart-scan`

Runtime profile: `v0.11.0-beta.6-b63.4-smart-scope`

Scope mode: `risk_prioritized_v1`

Scope guard: `exclude_pinned_runtime_root_v1`

## Verdict

**PASS — controlled cancellation was requested during a real pinned-runtime Smart Scan, accepted by the coordinator, propagated into the provider run, and finalized as `CANCELLED` without remediation authority.**

## Test configuration

```text
MaxFiles=250
MaxTotalMB=128
MaxFileMB=64
RecentDays=90
CancelAfterSeconds=2
```

The cancellation timer was armed only after the coordinator entered `RUNNING`.

## Observed live result

```text
accepted=true
executed=true
cancellation.requested=true
cancellation.request_accepted=true
cancellation.requested_after_seconds=2.0
state=CANCELLED
coverage=INCOMPLETE
completed_checks=3
total_checks=5
elapsed_ms=7219
no_destructive_authority=true
automatic_quarantine=false
automatic_repair=false
automatic_destructive_action=false
```

The result correctly remained incomplete after user cancellation. No clean/full-coverage claim was produced.

## Progress / interruption evidence

The live scan entered the Temp root and emitted file-level progress before cancellation. The visible sequence reached:

```text
Priority files inspected: 1/250
...
Priority files inspected: 18/250
Priority Smart Scan cancelled by the user.
```

At provider result level:

```text
smart_scope_01 = COMPLETED
smart_scope_02 = COMPLETED
smart_scope_03 = COMPLETED
smart_scope_04 = CANCELLED
smart_scope_05 = SKIPPED
```

The active Temp check had planned 221 files and returned 19 scanner reports before cancellation was honored. The following Roaming check was not executed and was explicitly represented as `SKIPPED`.

## Finding preservation during cancellation

One pre-cancellation low-severity heuristic finding was preserved in the final evidence rather than discarded:

```text
severity=LOW
category=static_malware_scan
assessment=temp_execution_candidate
```

This proves cancellation does not erase evidence already produced before the cancellation boundary.

The observed item was a temporary Microsoft Edge updater executable and was only reported for review. No quarantine, deletion, process termination, repair, registry/boot write, unlock, write mount, format, or reimage action was performed.

## Scope evidence

The declared Smart Scan plan remained bounded to 250 selected files:

```text
Temp selected_count=221
Roaming selected_count=29
selected_count=250
full_filesystem_coverage=false
```

The pinned historical runtime subtree remained excluded by the exact self-managed runtime guard.

## Safety interpretation

This PASS verifies the real Windows/pinned-runtime cancellation path across:

`SmartScanCoordinator.request_cancel()` -> provider `cancel_check` -> active file-by-file scan loop -> cancelled check result -> skipped remaining checks -> terminal `CANCELLED` result.

Cancellation is therefore not only a deterministic fixture behavior; it has now been observed during real historical `StaticScanner.scan_file(...)` execution.

## Remaining B6-3 live gate

Performance/scope, finding translation, and real cancellation are now live-accepted. Remaining work before B6-3 stabilization is primarily:

1. real Home/UI run with the accepted pinned provider;
2. verify the UI remains responsive while scanning;
3. verify file-level progress is visibly rendered during the real scan;
4. verify the UI cancel control drives the same accepted cancellation path;
5. final predecessor/Windows gate and supported-Windows evidence.

Do not promote B6-3 to stable or advance B6-4 until the final live UI/stabilization gate is complete.
