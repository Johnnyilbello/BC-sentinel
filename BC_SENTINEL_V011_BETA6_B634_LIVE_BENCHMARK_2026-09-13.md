# BC Sentinel v0.11.0-beta.6 — B6-3.4 Live Performance Benchmark

Date: 2026-09-13

Status: **PERFORMANCE TARGET PROVISIONALLY MET / LIVE ACCEPTANCE INCOMPLETE / RETEST REQUIRED**

## Runtime and policy

The real SHA-256-pinned historical FULL runtime was executed through the B6-3.4 risk-prioritized `scan_file` path.

```text
provider_profile=v0.11.0-beta.6-b63.4-smart-scope
scope_mode=risk_prioritized_v1
max_files=250
max_total_bytes=128 MB
max_file_bytes=64 MB
recent_days=90
full_filesystem_coverage=false
```

No automatic quarantine, repair or destructive authority was present.

## Observed benchmark

```text
selected_count=250
elapsed_ms=15610
completed_checks=4/5
coverage=INCOMPLETE
state=INCOMPLETE
no_destructive_authority=true
```

The previous broad `scan_paths` acceptance took about 86 minutes and behaved like a deep/full scan. This 15.61-second result is therefore a material performance improvement, but it is not an apples-to-apples coverage comparison: B6-3.4 intentionally executes a bounded risk-prioritized Smart Scan rather than whole-root scanning.

Selected scope included 220 files from Local Temp and 29 from Roaming. Desktop and Documents had no selected files under the global 250-file priority budget. One selected Downloads candidate failed before evidence was produced.

## Finding translation evidence

The real run preserved seven distinct findings from the selected Temp scope, including controlled BC Sentinel test fixtures and one LOW heuristic assessment on a Microsoft Edge updater executable in Temp. These findings are evidence that live historical assessment translation works; they are not an instruction to quarantine or delete any file automatically.

## Cause of INCOMPLETE

The only failed planned file was inside the exact pinned historical BC Sentinel runtime tree. The historical scanner intentionally refused it with:

```text
BC Sentinel self-managed path excluded from normal scanning.
```

This exposed a planner/scanner contract mismatch: B6-3.4 could schedule a file that the authoritative historical scanner is guaranteed to refuse.

The fail-closed result was correct: the run remained `INCOMPLETE` rather than being promoted to CLEAN or FINDINGS with incomplete evidence.

## Stabilization fix

B6-3.4 now excludes **only the exact pinned runtime root** from Smart Scan candidate planning before the global budget is allocated.

Guard:

```text
exclude_pinned_runtime_root_v1
```

This is deliberately not a broad `bc-sentinel-*` name exclusion. Other BC Sentinel-looking directories and arbitrary Temp paths remain eligible for normal risk-prioritized inspection.

Regression coverage verifies that a runtime nested below Downloads is excluded while an ordinary risky file outside that exact runtime remains scanned and can complete normally.

Windows CI after the guard:

```text
Workflow: B6-3 Smart Scan Gate
Run: 34764439517 (#35)
Head: e52960b42d4dda4467f16f080d709da57ca371e7
Result: success
Regression suite: 110 passed, 34 warnings
```

## Required next evidence

Repeat the same real Windows 250-file benchmark on head `e52960b42d4dda4467f16f080d709da57ca371e7`.

Expected accepted terminal state is `COMPLETED_FINDINGS` if the controlled/test findings remain, or `COMPLETED_CLEAN` if no finding survives the selected scope. Any new per-file evidence failure must remain fail-closed and blocks B6-3.4 live acceptance.

B6-3 remains non-stable. B6-0 remains the latest stable checkpoint.
