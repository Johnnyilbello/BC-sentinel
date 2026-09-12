# BC Sentinel v0.11.0-beta.6 — B6-3 Implementation Status

Status: **B6-3.0 ORCHESTRATION CI GREEN / B6-3.1 PROVIDER BOUNDARY CI GREEN / B6-3.2 PINNED STATICSCANNER ADAPTER IMPLEMENTED / REAL WINDOWS LIVE ACCEPTANCE PENDING**

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

### Local helper / preflight

Configure and pin the FULL runtime for the current PowerShell session:

```powershell
.\PIN-V011-BETA6-B63-FULL-RUNTIME.ps1 -RuntimeRoot "<FULL_RUNTIME_ROOT>"
```

Then run capability/import preflight only:

```powershell
.\.venv\Scripts\python.exe -m tools.v011_beta6_b63_live_runtime_probe
```

Only after preflight acceptance, explicitly run a live Smart Scan:

```powershell
.\.venv\Scripts\python.exe -m tools.v011_beta6_b63_live_runtime_probe --execute --output .\acceptance-v011-beta6-b63-live.json
```

## Automated evidence

The deterministic B6-3 gate now includes dedicated adapter tests for:

- missing runtime pin -> unavailable;
- scanner SHA mismatch -> unavailable;
- valid pinned runtime -> accepted;
- clean StaticScanner result -> complete clean;
- explicit detection -> preserved finding;
- unknown report schema -> incomplete, never clean;
- runtime import failure -> unavailable;
- exact configured root scope.

The normal B6-3 gate deliberately clears live-runtime environment variables before offscreen smoke, proving that the default/unpinned application remains fail-closed.

A fresh Windows CI pass is required after this B6-3.2 implementation before calling its deterministic gate green.

## Remaining B6-3 stabilization gate

B6-3 is not stable until real Windows evidence proves the pinned FULL runtime path:

1. B6-3 deterministic CI PASS with adapter tests;
2. local FULL-runtime preflight reports `accepted=true`;
3. explicit live scan on harmless controlled fixtures;
4. correct real report-shape translation;
5. clean/findings/incomplete/cancel behavior confirmed;
6. UI remains responsive during real scan;
7. no target mutation/remediation;
8. B6-0/B6-1/B6-2 predecessors remain green;
9. supported Windows acceptance evidence committed.

## Stable state

Until those requirements pass, the latest accepted stable checkpoint remains:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```
