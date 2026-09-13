# BC Sentinel v0.11.0-beta.6 — B6-3 Implementation Status

Status: **B6-3.0 ORCHESTRATION PASS / B6-3.1 PROVIDER BOUNDARY PASS / B6-3.2 PINNED STATICSCANNER ADAPTER PASS / B6-3.3 LIVE COMPATIBILITY PASS / B6-3.4 PERFORMANCE + FINDINGS + CANCELLATION LIVE PASS / B6-3.5 LIVE HOME UI COMPLETE + CANCEL PASS / FINAL WINDOWS CI GATE PENDING**

Primary branch: `feature/v011-beta6-b63-smart-scan`

## Product-owner decision

Further visual polish remains intentionally deferred. Functional/security roadmap work continues first. The accepted B6-2 Dashboard visual contract remains the baseline and must not regress.

## B6-3.0 — Smart Scan orchestration

Implemented and accepted:

- typed plan/check/finding/progress/result models;
- states `IDLE`, `PLANNED`, `RUNNING`, `COMPLETED_CLEAN`, `COMPLETED_FINDINGS`, `INCOMPLETE`, `FAILED`, `CANCELLED`;
- explicit user start only;
- duplicate-start refusal;
- worker-thread execution;
- shared coordinator across Dashboard/sidebar/Scansione;
- truthful complete-vs-incomplete coverage;
- Advanced details preserve complete evidence;
- Full Scan remains disabled;
- no remediation/destructive authority.

`CLEAN` cannot be produced when declared coverage is incomplete.

## B6-3.1 — Fixed live provider boundary

Home loads only `sentinel.smart_scan_live_provider` through the fail-closed provider loader. Loading/factory validation never starts a scan and source/module presence alone never becomes runtime truth.

## B6-3.2 — Pinned historical StaticScanner adapter

Accepted path:

```text
New Home
  -> SmartScanCoordinator
  -> sentinel.smart_scan_live_provider
  -> pinned historical FULL runtime subprocess
  -> sentinel.scanner.StaticScanner.scan_file(...)
```

The historical runtime is accepted only when the pinned `scanner.py` SHA-256 matches and the required scanner API is callable. No automatic quarantine, repair, process kill, delete, registry/boot write, unlock, write mount, format or reimage authority is added.

Pinned scanner SHA-256:

```text
7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433
```

## B6-3.3 — Real report compatibility + Unicode transport

The first broad live run exposed the real nested `assessment` schema and a Windows console Unicode transport failure. Compatibility handling now recognizes accepted historical assessment levels while unknown values remain fail-closed. Child-process transport is Unicode-safe.

Controlled narrow live acceptance:

```text
provider accepted=true
executed=true
completed_checks=1/1
coverage=COMPLETE
state=COMPLETED_CLEAN
reports=1
recognized_reports=1
findings_count=0
no_destructive_authority=true
```

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B63_LIVE_ACCEPTANCE_2026-09-13.md
```

## B6-3.4 — Smart Scan Performance & Scope Engine

The old broad run took about 86 minutes and behaved like a deep/full scan. B6-3.4 introduced a bounded risk-prioritized Smart Scan using `scan_file()` on selected candidates instead of broad `scan_paths()` over entire roots.

Profile:

```text
v0.11.0-beta.6-b63.4-smart-scope
```

Mode:

```text
risk_prioritized_v1
```

Key semantics:

- `full_filesystem_coverage=false`;
- `coverage=COMPLETE` means the declared bounded Smart Scan plan completed, not whole-disk coverage;
- candidate priority covers executable/script, macro, archive/container, persistence/startup, recency and risk-bearing locations;
- exact pinned runtime subtree is excluded before budget allocation via `exclude_pinned_runtime_root_v1`;
- per-file progress is emitted;
- file/report errors or unknown evidence cannot become `COMPLETED_CLEAN`.

### Live performance + finding acceptance — PASS

```text
selected_count=250
completed_checks=5/5
coverage=COMPLETE
state=COMPLETED_FINDINGS
elapsed_ms=18188
Temp selected=221
Roaming selected=29
no_destructive_authority=true
```

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B634_LIVE_BENCHMARK_R2_2026-09-13.md
```

### Live coordinator cancellation — PASS

```text
cancellation.requested=true
cancellation.request_accepted=true
state=CANCELLED
coverage=INCOMPLETE
completed_checks=3/5
elapsed_ms=7219
no_destructive_authority=true
```

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B634_LIVE_CANCELLATION_2026-09-13.md
```

## B6-3.5 — Actual Home/UI live acceptance

The real Qt Home was exercised with the accepted pinned provider. The scan was launched by clicking the real Home Smart Scan control; UI responsiveness, progress rendering, result rendering, overflow and Advanced details were measured from the actual window.

### Complete-mode Home/UI — PASS

```text
state=COMPLETED_FINDINGS
coverage=COMPLETE
elapsed_ms=7984
findings_count=7
heartbeat_ticks_while_running=46
max_heartbeat_gap_ms≈110
progress_advanced=true
progress_sample_count=17
dashboard_horizontal_scroll_max=0
scan_page_horizontal_scroll_max=0
```

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B635_LIVE_UI_COMPLETE_2026-09-13.md
```

### Cancel-mode Home/UI — PASS

The actual `Annulla` button was clicked after two seconds of `RUNNING`.

```text
cancel_click_sent=true
state=CANCELLED
coverage=INCOMPLETE
elapsed_ms=7047
findings_count=1
heartbeat_ticks_while_running=36
max_heartbeat_gap_ms=125
progress_advanced=true
progress_sample_count=9
dashboard_horizontal_scroll_max=0
scan_page_horizontal_scroll_max=0
```

Canonical evidence:

```text
BC_SENTINEL_V011_BETA6_B635_LIVE_UI_CANCEL_2026-09-13.md
```

This proves that the UI Cancel control drives the accepted coordinator cancellation path without freezing the UI or enabling remediation.

## Non-blocking cleanup

PySide currently emits warnings when code attempts `button.clicked.disconnect()` without a matching connection. They did not affect Home construction, scanning, progress, cancellation or terminal state. Cleanup may be handled separately and must not be mixed with security behavior changes unless re-tested.

## Automated coverage

The deterministic Windows gate covers:

- B6-0/B6-1/B6-2 predecessor regression;
- B6-3 orchestration/passive-start contract;
- fail-closed provider loading and SHA pinning;
- historical assessment compatibility;
- Unicode transport;
- risk-prioritized scope and budgets;
- `scan_file` path instead of legacy broad Smart Scan fallback;
- exact pinned-runtime exclusion;
- clean/finding translation;
- per-file error -> `INCOMPLETE`;
- cancellation -> `CANCELLED`;
- monotonic progress;
- B6-3.5 live UI evidence contract;
- no destructive authority;
- six-page shell and zero horizontal overflow.

## Final B6-3 stabilization gate

All required real Windows runtime and Home/UI acceptance tests are now PASS.

Only the final promotion barrier remains:

1. run the complete B6-0/B6-1/B6-2 predecessor + B6-3 Windows CI gate on the final documentation/stabilization head;
2. confirm every step is green;
3. record the final supported-Windows evidence/checkpoint;
4. only then consider B6-3 stabilized and open B6-4.

Do not promote B6-3 or advance B6-4 before the final CI result is observed.

## Stable state

The accepted stable checkpoint remains unchanged until final B6-3 promotion:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```
