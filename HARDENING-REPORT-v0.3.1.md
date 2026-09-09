# BC Sentinel v0.3.1 Beta — Security Hardening Report

## Scope

Phase 1 hardens the existing BC Sentinel protection stack. No security feature was removed, the application was not rebuilt, and the premium UI/navigation remain the existing baseline except for exposing richer process attribution in threat details.

## A. ETW process → file attribution

Implemented:
- PID + PPID + process create-time correlation.
- Executable name/path and command line preservation.
- Background SHA-256 executable identity enrichment.
- Local Authenticode status + signer enrichment.
- Per-process recent modified-file context.
- PID-reuse protection: asynchronous identity is applied only if the process create-time still matches.
- ETW callbacks never perform executable hashing or PowerShell signature inspection directly.
- Telemetry service `attribute` / `process_chain` responses expose enriched metadata.

## B. Hash cache / redundant scans

Implemented:
- Persistent SHA-256 + SHA-1 cache keyed by canonical path + `mtime_ns` + size.
- SHA-256 and SHA-1 calculated in one read pass on cache miss.
- Recent cache is preloaded into scanner memory instead of doing one SQLite query per enumerated file.
- Cache writes are batched (up to 256 entries/transaction).
- Unchanged cache entries are not rewritten.
- Real-time monitor keeps a fingerprint cache and returns immediately for duplicate events on an unchanged file.
- If size/mtime changes while hashing or scanning, the verdict is discarded rather than associated with unstable content.

## C. Threat scoring / false positives

Implemented conservative multi-signal scoring:
- repeated variants of the same signal retain diminishing returns;
- weak heuristic-only evidence is capped below the user-facing SUSPICIOUS threshold;
- 3+ independent medium/strong signals receive only a small bounded convergence bonus;
- deterministic signature evidence remains authoritative;
- a valid Authenticode signature can reduce weak heuristic noise but cannot cancel deterministic evidence;
- explicit hash allowlisting suppresses scanning of that immutable content identity;
- publisher allowlisting is honored only when Authenticode reports `Valid`.

## D. Exclusions / allowlist hardening

Implemented:
- canonical path normalization;
- boundary-safe directory containment (`commonpath` semantics), no string-prefix fallback;
- validated SHA-1/SHA-256 allowlist values;
- file, directory, hash and publisher trust records;
- in-memory path allowlist snapshot for scan enumeration performance;
- live refresh-on-miss for uncommon hash/publisher allowlist changes.

## E. Path-trick protection

Implemented reusable `sentinel/path_security.py` protections:
- direct symlink detection;
- Windows reparse-point/junction leaf detection through `st_file_attributes`;
- recursive scanner pruning of reparse directories;
- security-sensitive write-parent validation;
- boundary-safe managed-directory checks.

BC Sentinel managed paths now cover application root, installed executable directory, LocalAppData data/quarantine, and BC Sentinel ProgramData.

## F. Quarantine / restore hardening

Quarantine now:
- rejects symlink/reparse sources and BC Sentinel managed files;
- snapshots size/mtime before and after reading and again before deletion;
- uses exclusive creation for encrypted objects;
- flushes + fsyncs encrypted storage;
- decrypts and verifies SHA-256 before deleting the original;
- rolls back DB/object state if quarantine cannot be completed.

Restore now:
- validates item IDs;
- rejects database records whose stored path escapes the quarantine directory;
- rejects reparse objects/parents and BC Sentinel managed destinations;
- never overwrites an existing destination;
- writes with exclusive creation + fsync;
- verifies the restored file SHA-256 before marking the item restored.

Quarantine key, SQLite DB and telemetry secret additionally receive reparse checks and best-effort restrictive permissions. Full same-user/admin tamper resistance remains a future privileged-service phase.

## G. Performance / stress validation

Final synthetic stress run in the delivery container:

| Metric | Result |
|---|---:|
| Corpus | 5,000 files × 256 B |
| Cold scan | 3.526 s |
| Cold throughput | 1418.13 files/s |
| Warm scan | 3.223 s |
| Warm throughput | 1551.12 files/s |
| Warm hash-cache hits | 5,000/5,000 |
| Cold RSS end | 102.6 MiB |
| Warm RSS end | 106.6 MiB |
| Real-time pipeline workload | 10 executable-like harmless files |
| Real-time pipeline CPU | 0.85% of one core during measured fallback window |
| Unchanged repeat: 10 files | 0.000270 s |

The 5,000-file stress directory completed with all files enumerated/scanned and all 5,000 hashes served from cache on the warm pass.

**Benchmark caveat:** `watchdog` is not installed in this Linux delivery container, so `started=false` and the real-time result is explicitly labelled `direct_pipeline_fallback`. It exercises the actual stability → fingerprint → scan pipeline, not the native filesystem Observer. Run the same tool on the Windows target with requirements installed to benchmark the real Observer.

`read_bytes` may report zero in this container because Linux page cache/accounting can satisfy reads without process-level physical-read counters increasing. Treat the included I/O counters as environment-specific, not universal disk benchmarks.

Benchmark command:

```text
python -m tools.security_benchmark --files 5000 --size 256 --realtime-seconds 1 --output benchmark_v031.json
```

## H. Validation gate

- Full pytest suite: **132 passed**.
- All Python sources compile with `py_compile`.
- Existing 117-test baseline preserved; 15 hardening tests added.
- Tests cover hash-cache invalidation, allowlist boundary safety, hash validation, publisher-signature trust, PID reuse, enriched file attribution, weak-signal capping, multi-signal convergence, trust damping, symlink rejection, real-time duplicate fingerprint suppression, quarantine stored-path tampering, overwrite prevention and symlink quarantine rejection.

## Remaining hardening weaknesses

1. Native ETW + Authenticode + Windows reparse behavior still needs target-Windows acceptance testing.
2. Native watchdog Observer performance was not measurable in this container.
3. User-space permission hardening cannot stop an administrator or a malicious same-user process with sufficient access. True tamper protection belongs with the later Windows Service architecture.
4. Hash cache deliberately does not skip YARA/heuristic analysis during a manual scan solely because a hash is cached; rules may change. Real-time duplicate events *are* skipped when the file fingerprint is unchanged.
5. No kernel minifilter means there is still an unavoidable user-space observation/blocking gap.

## Main files changed / added

- `sentinel/path_security.py` — new
- `sentinel/process_identity.py` — new
- `sentinel/process_tree.py`
- `sentinel/correlation.py`
- `sentinel/etw_monitor.py`
- `sentinel/process_monitor.py`
- `sentinel/core/events.py`
- `sentinel/scanner.py`
- `sentinel/scoring.py`
- `sentinel/realtime.py`
- `sentinel/quarantine.py`
- `sentinel/database.py`
- `sentinel/reputation.py`
- `sentinel/telemetry_service_core.py`
- `sentinel/telemetry_client.py`
- `sentinel/config.py`
- `app/ui/main_window.py`
- `tools/security_benchmark.py` — new
- `sentinel/performance.py` — new
- `tests/test_v031_security_hardening.py` — new
- `tests/test_v031_quarantine_hardening.py` — new
