# BC Sentinel v0.11.0-beta.6 — B6-3 Live Runtime Acceptance Evidence

Date: 2026-09-13
Branch: `feature/v011-beta6-b63-smart-scan`

## Scope

This checkpoint records the first successful controlled live Windows acceptance of the pinned historical `StaticScanner` adapter after B6-3.3 runtime-compatibility hardening.

## Runtime binding

Verified historical runtime scanner:

```text
sentinel.scanner.StaticScanner.scan_paths
```

Pinned scanner SHA-256:

```text
7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433
```

Provider:

```text
BC Sentinel StaticScanner live adapter
v0.11.0-beta.6-b63.2-static-scanner
pinned_full_runtime:sentinel.scanner.StaticScanner.scan_paths
```

## Preflight result

PASS:

- provider loaded: `true`
- provider accepted: `true`
- capability contract passed: `true`
- runtime probe imported `StaticScanner`: `true`
- `scan_paths` callable: `true`
- automatic quarantine: `false`
- automatic repair: `false`
- automatic destructive action: `false`

## Controlled live fixture

A narrow temporary scan root was used instead of the full default Smart Scan scope.

The fixture filename intentionally included Unicode punctuation to re-test the Windows console/IPC encoding failure discovered during the first broad live run.

Fixture content was harmless:

```text
Write-Output 'BC Sentinel benign fixture'
```

## Live result

PASS:

```text
executed=true
completed_checks=1
total_checks=1
coverage=COMPLETE
state=COMPLETED_CLEAN
findings_count=0
no_destructive_authority=true
elapsed_ms=157
```

The historical report was successfully translated through the B6-3.3 compatibility layer:

```text
reports=1
recognized_reports=1
status=COMPLETED
```

This proves that the compatibility layer now accepts the real historical `assessment` report schema for a benign result and transports a Unicode path without the prior `UnicodeEncodeError`.

## Previous broad-run findings that drove B6-3.3

The first full-scope live run was intentionally fail-closed and ended `INCOMPLETE` because:

1. the original adapter did not yet classify the historical nested `assessment` schema;
2. `Temp` and `Roaming` could fail on Windows console `cp1252` when a scanned path contained unsupported Unicode characters.

B6-3.3 added runtime compatibility handling while preserving fail-closed semantics for unknown report shapes.

## What this acceptance proves

- the pinned historical runtime can be bound from the current B6 branch;
- the fixed provider loader accepts the live adapter only after capability validation;
- a real `StaticScanner.scan_paths` call executes from the modern Smart Scan orchestration;
- the real historical report shape is translated successfully for the tested clean case;
- Unicode path transport no longer fails for the tested case;
- complete coverage can produce `COMPLETED_CLEAN` only when the planned check really completes;
- no remediation/destructive authority is introduced.

## What remains open

B6-3 is not yet stable. The following still require acceptance before promotion:

- real live finding translation using a harmless controlled detection fixture;
- real cancellation during an active live scan;
- real UI responsiveness and progress display while the historical scanner is running;
- performance/scope redesign for consumer Smart Scan: the first broad run took about 86 minutes and scanned hundreds of thousands of files, so it is too slow to qualify as the final Smart Scan experience;
- broader Windows acceptance after the performance/scope changes;
- predecessor gates must remain green.

## Status

`B6-3.3 LIVE RUNTIME COMPATIBILITY NARROW ACCEPTANCE: PASS`

`B6-3 STABILIZATION: IN PROGRESS`
