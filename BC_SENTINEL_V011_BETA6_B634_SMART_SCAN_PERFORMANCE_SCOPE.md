# BC Sentinel v0.11.0-beta.6 — B6-3.4 Smart Scan Performance & Scope Engine

Status: **IMPLEMENTED / WINDOWS DETERMINISTIC CI GREEN / REAL PINNED WINDOWS PERFORMANCE ACCEPTANCE PENDING**

Development branch: `feature/v011-beta6-b634-smart-scan-scope`

## Why B6-3.4 exists

The first broad live B6-3 scan proved that the historical `StaticScanner` could be invoked, but its default monitored-root sweep behaved more like a deep scan than a consumer Smart Scan. The real run took about 86 minutes and traversed hundreds of thousands of reports. That behavior is valid evidence for the historical engine, but it is not an acceptable default Quick/Smart Scan experience.

B6-3.4 therefore separates two concepts explicitly:

- **Smart Scan**: a bounded, risk-prioritized inspection of recent/high-risk candidates;
- **Full Scan**: broad filesystem coverage, still disabled in B6-3 and not silently approximated by Smart Scan.

`coverage=COMPLETE` in B6-3.4 means that every file selected by the declared Smart Scan plan produced accepted evidence. It does **not** claim that every file on the machine was scanned. The plan/evidence explicitly records `full_filesystem_coverage=false`.

## Architecture

```text
Home / SmartScanCoordinator
        -> fail-closed provider loader
        -> B6-3.3 compatibility boundary
        -> B6-3.4 risk-prioritized scope
        -> SHA-256-pinned historical runtime
        -> StaticScanner.scan_file(candidate)
```

The historical scanner remains authoritative for file inspection. B6-3.4 changes the selection/orchestration boundary only; it does not rewrite the old security engine.

If the pinned runtime does not prove that `StaticScanner.scan_file` is callable, B6-3.4 does not fake support. The compatibility layer falls back to the B6-3.2 `scan_paths` provider. Real B6-3.4 acceptance must therefore verify the B6-3.4 provider profile before execution.

## Default Smart Scan policy

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
max selected files: 1200
max selected bytes: 384 MB
max individual file: 128 MB
recent window: 180 days
full filesystem coverage: false
```

The policy can be bounded for acceptance/benchmarking through:

```text
BC_SENTINEL_SMART_SCAN_MAX_FILES
BC_SENTINEL_SMART_SCAN_MAX_TOTAL_BYTES
BC_SENTINEL_SMART_SCAN_MAX_FILE_BYTES
BC_SENTINEL_SMART_SCAN_RECENT_DAYS
```

The PowerShell runtime helper exposes equivalent `-MaxFiles`, `-MaxTotalMB`, `-MaxFileMB`, and `-RecentDays` parameters.

## Candidate selection

The current scope prioritizes security-relevant candidates such as:

- executable/PE-like and script extensions already recognized by BC Sentinel;
- macro-enabled Office documents;
- archives and disk-image containers;
- selected document/link types with execution or delivery relevance;
- startup/persistence-path candidates;
- recent content in Downloads, Temp, Roaming, Desktop and Documents.

Priority is increased by risk-bearing location and recency. Startup/persistence paths receive additional priority.

Common development/build trees such as `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `dist`, `build` and `site-packages` are excluded from Smart Scan candidate discovery. This is a performance-scope decision for Smart Scan only, not a global antivirus exclusion or Full Scan rule.

Symlinks are not followed during candidate discovery.

## Truth and fail-closed semantics

B6-3.4 preserves the existing B6-3 truth contract:

- no candidate list or scan is created at import time;
- no automatic quarantine or repair;
- no process termination, file deletion, registry/boot write, unlock, write mount, format or reimage authority;
- per-file scanner errors make the affected check incomplete;
- unknown/unrecognized historical reports never become clean;
- a selected file without accepted evidence prevents `COMPLETED_CLEAN`;
- cancellation stops between selected files and results in incomplete coverage;
- findings returned by the historical `assessment` model are preserved;
- Unicode transport remains hardened by the B6-3.3 boundary.

## Progress model

The original adapter exposed mainly root/check-level progress. B6-3.4 emits progress as selected files are inspected, while preserving the coordinator's monotonic 0–100 contract.

This gives the Home/UI meaningful progress during a real Smart Scan instead of appearing frozen for an entire root.

## Automated acceptance

Dedicated B6-3.4 tests verify:

- risky candidate selection and development-noise exclusion;
- highest-risk-first budget behavior;
- accepted runtime uses `scan_file`, not the broad `scan_paths` path;
- clean assessment -> complete clean;
- historical HIGH assessment -> preserved finding;
- per-file failure -> `INCOMPLETE`, never clean;
- cancellation while files are actively being scanned -> `CANCELLED`;
- monotonic file-level progress;
- explicit `full_filesystem_coverage=false` evidence;
- no destructive authority.

Windows workflow evidence on the B6-3.4 branch has passed with the B6-0/B6-1/B6-2/B6-3 predecessor regression suite intact.

## Remaining live gate

B6-3.4 is not accepted as a live performance milestone until a real pinned Windows run proves:

1. provider profile is `v0.11.0-beta.6-b63.4-smart-scope`;
2. scope mode is `risk_prioritized_v1`;
3. selected/candidate counts and byte budget are recorded;
4. elapsed time is materially below the previous broad ~86-minute scan for the tested machine/profile;
5. progress advances during the real scan;
6. controlled harmless finding translation remains correct;
7. real cancellation works during active scanning;
8. no target mutation/remediation occurs;
9. predecessor gates remain green.

Do not promote B6-3 or advance B6-4 until the live B6-3 stabilization gate is complete.
