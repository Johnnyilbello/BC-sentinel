# BC Sentinel v0.3.1 Beta — Security Hardening

This release hardens the existing protection stack without redesigning the app or adding a new detection product surface.

## Detection and attribution
- ETW process/file attribution now preserves PID, PPID, executable path, command line, process create-time, SHA-256, Authenticode status/signer and modified-file context.
- Process identity hashing and signature inspection run asynchronously, outside the ETW callback path.
- PID reuse protection prevents stale identity data from being attached to a different process that later receives the same PID.
- Telemetry service process-chain responses now expose the enriched identity and recent modified files.

## Hashing and scan efficiency
- Added persistent SHA-256 + SHA-1 cache keyed by canonical path, mtime_ns and size.
- Multiple digests are computed in one file read.
- Manual scan cache writes are batched and unchanged cache rows are not rewritten.
- Scanner preloads recent hash and allowlist data to avoid one SQLite connection per enumerated file.
- Real-time scanning skips repeat events for the exact same unchanged fingerprint.
- Verdicts are discarded if a file changes while being hashed/scanned.

## Scoring / false-positive hardening
- Weak heuristic-only evidence is capped below user-facing detection level.
- Independent medium/strong signals receive a small bounded convergence bonus.
- Valid Authenticode can dampen weak heuristic noise but never cancels deterministic signature evidence.
- Hash and publisher allowlists are supported; publisher trust only applies to a `Valid` Authenticode signature.

## Path and exclusion hardening
- File/directory allowlists use canonical, boundary-safe containment rather than string-prefix matching.
- Hash allowlist inputs are validated as SHA-1/SHA-256 hex digests.
- Scanner rejects direct symlink/reparse-point targets and prunes reparse directories during recursive scans.
- Managed paths now include the installed executable directory, application/data/quarantine paths and BC Sentinel ProgramData.

## Quarantine / restore hardening
- Quarantine rejects managed files and symlink/reparse-point sources.
- Source snapshots are checked before deletion to detect mid-operation modification.
- Encrypted quarantine objects are persisted with exclusive creation + fsync and decrypted/hashed again before the original is removed.
- Database records that point outside the managed quarantine directory are rejected.
- Restore uses exclusive destination creation, refuses overwrites/reparse parents/BC Sentinel managed destinations and verifies the restored SHA-256 before marking success.
- Quarantine key and telemetry secret reject reparse-point redirection and use best-effort restrictive permissions.

## Performance / validation
- Added `tools/security_benchmark.py` for repeatable scan and real-time-pipeline CPU/RAM/I/O measurements.
- Added v0.3.1 hardening regression tests.
- Full suite: **132 passed** in the delivery environment.
- Synthetic 5,000-file stress corpus completed successfully; see `HARDENING-REPORT-v0.3.1.md` and `benchmark_v031.json`.

## Known limitation
The delivery container does not have `watchdog` installed, so the native observer could not be benchmarked here. The benchmark explicitly labels and measures the real-time stabilization/scan pipeline fallback instead. Native Windows/watchdog validation remains required on the target machine.
