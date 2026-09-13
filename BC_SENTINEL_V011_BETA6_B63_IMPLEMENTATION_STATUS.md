# BC Sentinel v0.11.0-beta.6 — B6-3 Implementation Status

Status: **B6-3.0 ORCHESTRATION CI GREEN / B6-3.1 PROVIDER BOUNDARY CI GREEN / B6-3.2 PINNED STATICSCANNER ADAPTER IMPLEMENTED / B6-3.3 LIVE COMPATIBILITY NARROW PASS / B6-3.4 PERFORMANCE & SCOPE WINDOWS CI GREEN / LIVE PERFORMANCE ACCEPTANCE PENDING**

Primary B6-3 branch: `feature/v011-beta6-b63-smart-scan`

B6-3.4 integration branch: `feature/v011-beta6-b634-smart-scan-scope`

## Product-owner decision

Further UI polishing is intentionally deferred. Functional/security roadmap work continues first. The accepted B6-2 Dashboard visual contract remains the UI baseline and must not regress.

## B6-2 predecessor

B6-2 Home / Security Overview remains automated-Windows-CI green, including responsive geometry and runtime-truth checks. Manual product-owner visual acceptance and additional polish remain open, so B6-2 has not replaced B6-0 as the latest stable checkpoint.

## B6-3.0 — Smart Scan orchestration foundation

Implemented:

- typed Smart Scan plan/check/finding/progress/result models;
- explicit session states: `IDLE`, `PLANNED`, `RUNNING`, `COMPLETED_CLEAN`, `COMPLETED_FINDINGS`, `INCOMPLETE`, `FAILED`, `CANCELLED`;
- complete-vs-incomplete coverage semantics;
- explicit user start only, duplicate-start refusal and cancellation;
- worker-thread integration so scan work does not run on the GUI thread;
- one shared coordinator for Dashboard, sidebar and Scansione;
- Advanced details preserve complete evidence;
- Full Scan remains disabled;
- no destructive/remediation authority.

`CLEAN` cannot be produced when the declared plan is incomplete.

## B6-3.1 — Live provider boundary

The Home loads only the fixed adapter module `sentinel.smart_scan_live_provider` through `sentinel.smart_scan_provider_loader`.

The loader remains fail-closed and never starts a scan during import/factory validation. Provider availability is not inferred from source/module presence alone.

## B6-3.2 — Pinned historical StaticScanner adapter

The historical FULL Windows runtime exposes the real on-demand APIs:

```text
sentinel.scanner.StaticScanner.scan_paths(...)
sentinel.scanner.StaticScanner.scan_file(...)
```

The adapter keeps the historical engine outside the current B6 package and invokes it in a separate Python process. The runtime is unavailable unless `sentinel/scanner.py` exists, its SHA-256 matches the explicit pin, the selected Python can import `StaticScanner`, and the required scanner method is callable.

No automatic quarantine, repair, process kill, registry/boot write, unlock, write mount, format or reimage authority is added.

## B6-3.3 — Historical report compatibility and Unicode transport

The first real broad Windows scan successfully invoked the historical scanner but exposed two compatibility gaps:

1. real `FileReport` payloads use a nested `assessment` object (`level`, `score`, `reasons`, `signals`, `confidence`), not only the simplified `verdict/detections` shape used in the first adapter fixtures;
2. Windows console `cp1252` could fail while transporting paths containing unsupported Unicode characters.

The broad run correctly ended `INCOMPLETE` instead of claiming `CLEAN`.

B6-3.3 added a compatibility layer for the real assessment vocabulary and hardened Unicode child-process transport. Unknown assessment levels remain fail-closed.

### Controlled narrow live Windows acceptance — PASS

A harmless Unicode-named fixture was scanned through the real pinned FULL runtime with:

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

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B63_LIVE_ACCEPTANCE_2026-09-13.md
```

## B6-3.4 — Smart Scan Performance & Scope Engine

The first broad live run took about 86 minutes and produced hundreds of thousands of reports. That proved historical engine execution, but it behaved more like a deep/full scan than a consumer Smart Scan.

B6-3.4 now separates Smart Scan from Full Scan explicitly. When the accepted pinned runtime proves `StaticScanner.scan_file` is callable, the provider uses a bounded risk-prioritized scope and scans selected candidates file-by-file instead of invoking broad `scan_paths` over entire monitored roots.

Profile:

```text
v0.11.0-beta.6-b63.4-smart-scope
```

Scope mode:

```text
risk_prioritized_v1
```

Default policy:

```text
max files: 1200
max selected bytes: 384 MB
max individual file: 128 MB
recent window: 180 days
full filesystem coverage: false
```

Candidate priority covers executable/script types, macro documents, selected archives/disk images, relevant link/document types, persistence/startup paths, recency and risk-bearing locations such as Downloads/Temp/Roaming. Common development/build trees are excluded from **Smart Scan scope only**; this is not a global antivirus exclusion and does not define Full Scan behavior.

The provider records `full_filesystem_coverage=false`. `coverage=COMPLETE` means the declared bounded Smart Scan plan completed with accepted evidence for every selected file; it does not claim whole-disk coverage.

B6-3.4 also adds file-level progress, so progress can move while a root is being inspected rather than appearing frozen until the entire root completes.

Fail-closed behavior remains intact: per-file errors, missing evidence, unknown report semantics or incomplete planned coverage cannot become `COMPLETED_CLEAN`.

Canonical contract:

```text
BC_SENTINEL_V011_BETA6_B634_SMART_SCAN_PERFORMANCE_SCOPE.md
```

## Automated evidence

Windows deterministic evidence now covers:

- B6-0/B6-1/B6-2 predecessor regression;
- B6-3 orchestration and passive-start contract;
- fail-closed provider loading and SHA-256 runtime pinning;
- real historical assessment-schema compatibility;
- Unicode transport;
- risk-prioritized candidate selection;
- highest-risk-first file/byte budgets;
- use of `scan_file` rather than broad `scan_paths` in B6-3.4;
- clean and finding translation;
- per-file failure -> `INCOMPLETE`;
- active cancellation -> `CANCELLED`;
- monotonic file-level progress;
- no destructive authority;
- six-page shell and zero horizontal overflow.

Observed Windows run on B6-3.4 code:

```text
Workflow: B6-3 Smart Scan Gate
Run: 34763211770
Head: 15f992380809b68f8ecaf8deeccab3112c296b91
Result: success
Regression suite: 109 passed, 34 warnings
```

A later helper-only head also passed the same Windows gate before this documentation update.

## Remaining B6-3 stabilization gate

B6-3 is not stable yet. Remaining live acceptance work:

1. real pinned Windows B6-3.4 performance benchmark with `provider_profile=v0.11.0-beta.6-b63.4-smart-scope`;
2. verify selected candidate/file/byte scope and materially lower elapsed time than the prior ~86-minute broad run;
3. controlled live harmless **finding** translation;
4. real cancellation during active pinned-runtime scanning;
5. UI responsiveness and visible progress during a real B6-3.4 scan;
6. no target mutation/remediation;
7. final B6-0/B6-1/B6-2 predecessor gate remains green;
8. supported-Windows evidence committed.

Do not advance B6-4 until the B6-3 live Smart Scan stabilization gate is complete.

## Stable state

The latest accepted stable checkpoint remains unchanged:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```
