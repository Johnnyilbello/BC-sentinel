# BC Sentinel v0.11.0-beta.6 — B6-3 Implementation Status

Status: **B6-3.0 ORCHESTRATION CI GREEN / B6-3.1 PROVIDER BOUNDARY CI GREEN / B6-3.2 PINNED STATICSCANNER ADAPTER IMPLEMENTED / B6-3.3 LIVE RUNTIME COMPATIBILITY NARROW ACCEPTANCE PASS / STABILIZATION IN PROGRESS**

Development branch: `feature/v011-beta6-b63-smart-scan`

## Product-owner decision

Further UI polishing is intentionally deferred. Functional/security roadmap work continues first. The accepted B6-2 Dashboard visual contract remains the UI baseline and must not regress.

## B6-2 predecessor

B6-2 Home / Security Overview is automated-Windows-CI green, including responsive geometry and runtime-truth checks. Manual product-owner visual acceptance and additional polish remain open, so B6-2 has not replaced B6-0 as the latest stable checkpoint.

## B6-3.0 — Smart Scan orchestration foundation

Implemented:

- typed Smart Scan plan/check/finding/progress/result models;
- explicit session states: `IDLE`, `PLANNED`, `RUNNING`, `COMPLETED_CLEAN`, `COMPLETED_FINDINGS`, `INCOMPLETE`, `FAILED`, `CANCELLED`;
- complete-vs-incomplete coverage semantics;
- provider capability contract and provenance;
- explicit user start only;
- duplicate-start refusal;
- cancellation;
- monotonic bounded progress;
- Qt worker-thread integration so scan work does not run on the GUI thread;
- one shared Smart Scan coordinator for Dashboard, sidebar and Scansione page;
- Advanced details preserve complete result/evidence payload;
- Full Scan remains disabled;
- no automatic quarantine, repair, process termination, file deletion, registry/boot write, unlock, write mount, format or reimage authority.

`CLEAN` cannot be produced when planned coverage is missing.

## B6-3.1 — Live provider boundary

The Home loads only the fixed adapter module:

```text
sentinel.smart_scan_live_provider
```

through:

```text
sentinel.smart_scan_provider_loader
```

The loader remains fail-closed and never starts a scan during import/factory validation.

## B6-3.2 — Pinned historical StaticScanner adapter

The runtime audit of the full Windows package established the real on-demand API:

```text
sentinel.scanner.StaticScanner.scan_paths(...)
sentinel.scanner.StaticScanner.scan_file(...)
```

and confirmed that the historical UI itself used `scan_paths(...)` for Quick/Full Scan.

Implemented adapter:

```text
sentinel.smart_scan_live_provider
```

Architecture:

```text
Home / SmartScanCoordinator
        -> fixed live-provider loader
        -> SHA-256-pinned external full runtime
        -> isolated Python subprocess
        -> sentinel.scanner.StaticScanner.scan_paths
```

The historical FULL runtime is not copied over the current B6 code and no security engine file is rewritten. The adapter runs the old scanner in its own Python package context, preventing accidental mixing of the modern Home package with historical scanner-relative dependencies.

### Runtime acceptance requirements

The adapter is unavailable unless all of these are true:

1. `BC_SENTINEL_FULL_RUNTIME_ROOT` points to a runtime containing `sentinel/scanner.py`;
2. `BC_SENTINEL_FULL_RUNTIME_SCANNER_SHA256` contains the exact SHA-256 of that file;
3. the selected Python executable can import `sentinel.scanner.StaticScanner`;
4. `StaticScanner.scan_paths` is callable;
5. at least one configured Smart Scan root exists.

Optional:

```text
BC_SENTINEL_FULL_RUNTIME_PYTHON
BC_SENTINEL_SMART_SCAN_ROOTS
```

Without an explicit root override, the adapter uses the existing `Settings.defaults().monitored_dirs` scope.

### Safety semantics

- no scan at module import or provider factory time;
- external runtime path alone is not trusted: scanner SHA-256 pin is mandatory;
- the provider calls only `StaticScanner.scan_paths`;
- cancellation is relayed through the scanner's existing `cancelled=` callback using a cancellation marker;
- no automatic quarantine;
- no automatic repair;
- no process kill/remediation authority;
- no registry/boot write;
- no unlock/write mount/format/reimage;
- unknown/unrecognized historical report shapes fail to `INCOMPLETE`, never `CLEAN`;
- subprocess/import failure fails closed;
- progress is check/root based and monotonic.

## B6-3.3 — Historical report compatibility and Unicode transport

The first real broad Windows scan successfully invoked the historical scanner but exposed two real compatibility gaps:

1. historical `FileReport` payloads use a nested `assessment` object (`level`, `score`, `reasons`, `signals`, `confidence`) rather than the simplified `verdict/detections` fixture shape used in the first adapter tests;
2. Windows console `cp1252` could fail while transporting scanned paths containing unsupported Unicode characters.

The broad run correctly ended `INCOMPLETE` rather than claiming `CLEAN`.

B6-3.3 adds a dedicated compatibility layer for the real historical report schema and hardened Unicode subprocess transport. Unknown report semantics remain fail-closed.

### Controlled narrow live Windows acceptance — PASS

A harmless temporary fixture with an intentionally Unicode filename was scanned through the real pinned FULL runtime.

Observed result:

```text
provider loaded=true
provider accepted=true
executed=true
completed_checks=1
total_checks=1
coverage=COMPLETE
state=COMPLETED_CLEAN
reports=1
recognized_reports=1
findings_count=0
no_destructive_authority=true
elapsed_ms=157
```

This proves for the tested clean case that:

- the fixed loader accepts the pinned live provider;
- the modern coordinator executes the real `StaticScanner.scan_paths` path;
- the historical `assessment` report is translated as auditable evidence;
- the Unicode filename survives transport without the previous `UnicodeEncodeError`;
- complete coverage is required before `COMPLETED_CLEAN`;
- no automatic remediation/destructive authority was added.

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B63_LIVE_ACCEPTANCE_2026-09-13.md
```

## Automated evidence

The deterministic B6-3 gate includes adapter/runtime compatibility tests for:

- missing runtime pin -> unavailable;
- scanner SHA mismatch -> unavailable;
- valid pinned runtime -> accepted;
- clean result -> complete clean;
- explicit detection -> preserved finding;
- unknown report schema -> incomplete, never clean;
- historical nested `assessment` schema translation;
- unknown assessment level -> incomplete/fail-closed;
- Unicode child-process transport;
- runtime import failure -> unavailable;
- exact configured root scope.

The normal B6-3 gate deliberately clears live-runtime environment variables before offscreen smoke, proving that the default/unpinned application remains fail-closed.

Latest Windows CI after B6-3.3 compatibility hardening:

```text
Workflow: B6-3 Smart Scan Gate
Run: 34762503470
Head: 5ed8cfa20be2b68ac84b3708da50634d9784bea0
Conclusion: success
```

## Remaining B6-3 stabilization gate

B6-3 is not stable yet. Remaining acceptance work:

1. controlled live **finding** translation with harmless detection evidence;
2. real cancellation during an active live scan;
3. UI responsiveness and visible progress during a real scan;
4. redesign Smart Scan scope/performance: the first broad scan took about 86 minutes and scanned hundreds of thousands of files, which is not acceptable as the final consumer Smart Scan experience;
5. broader Windows acceptance after performance/scope changes;
6. no target mutation/remediation;
7. B6-0/B6-1/B6-2 predecessors remain green;
8. final supported-Windows evidence committed.

Do not advance B6-4 until the B6-3 live Smart Scan stabilization gate is complete.

## Stable state

Until those requirements pass, the latest accepted stable checkpoint remains:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```
