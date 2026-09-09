# BC Sentinel v0.3.1 RC1 — Development & Adversarial Hardening Report

## Scope

This iteration continues Phase 1 on top of the existing v0.3.1 Security Hardened baseline. It does not add decorative product features. The goal is to close metadata/cache trust gaps, reduce race opportunities, preserve bulk-scan performance and create a repeatable native Windows acceptance gate.

## 1. Executable/content identity hardening

Implemented:

- security-sensitive executable/script extensions no longer trust the persistent hash cache based only on `mtime_ns + size`;
- accepted executable events in the real-time pipeline receive a real content scan rather than a 10-minute stat-only suppression;
- event-storm protection remains via the 2-second observer debounce;
- hash allowlist trust is re-verified against current bytes whenever its candidate digest came from metadata cache;
- process identity enrichment performs SHA-256 off the ETW callback thread for each new enrichment request;
- cached process identity is keyed only after the current SHA-256 is known;
- local file-reputation cache reuse now also requires matching SHA-256.

This closes the practical class of attacks where content is changed and the previous size/timestamp is restored to obtain stale trust.

## 2. Race/path hardening

Implemented:

- reusable file-snapshot comparison includes filesystem object identity (`st_dev` / `st_ino` where exposed) plus size and `mtime_ns`;
- scanner rejects a verdict if the path changed, was replaced or mutated during hashing/scanning;
- quarantine uses the stronger snapshot identity test;
- database path, WAL and SHM are checked for symlink/reparse redirection on every connection;
- sensitive DB connections enable foreign keys, disable trusted schema and use a consistent busy timeout.

Remaining limitation: a same-user administrator-level attacker can still win races that require kernel/file-handle semantics unavailable to a pure Python user-space engine. That remains a Windows Service/native-core phase concern.

## 3. Expanded security-sensitive file coverage

The real-time/security-sensitive extension set now includes the previous types plus:

- `.sys`
- `.ocx`
- `.cpl`
- `.hta`
- `.jar`
- `.lnk`

These types are treated conservatively for content identity/cache decisions.

## 4. Allowlist performance without stale trust

A first RC implementation exposed excessive SQLite traffic when refreshing hash/publisher allowlists during bulk scans. It was corrected with:

- an in-process allowlist revision counter for immediate changes made through the active `Database` instance;
- a bounded periodic refresh for changes made externally/through another instance;
- no SQLite lookup per ordinary hash miss.

This preserves quick trust updates while avoiding thousands of tiny DB transactions.

## 5. Real-time stabilization

The stable-file polling interval was reduced from 350 ms to 150 ms. The pipeline still waits for two matching stat snapshots before scanning but reacts faster after a writer settles.

The old 10-minute `mtime+size` real-time suppression was removed because those values are not a secure content identity.

## 6. Native Windows acceptance harness

Added:

`tools/windows_acceptance.py`

It safely checks the actual target machine for:

- Windows target/runtime;
- PySide6, watchdog, psutil, cryptography, YARA and ETW dependencies;
- native watchdog Observer delivery;
- ETW provider startup;
- local Authenticode inspection;
- NTFS junction/reparse detection;
- same-size/same-timestamp executable mutation handling;
- cold/warm scan performance;
- real-time pipeline performance.

Recommended target-machine command:

```text
python -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --output acceptance-v031-rc1.json
```

The harness does not require real malware.

## 7. Automated validation

Final local regression suite:

- **137 / 137 tests passed**.
- Python source compilation passes.
- New regression coverage includes timestamp-restoration executable mutation, hash-allowlist stale-cache verification, SHA-bound reputation reuse, process identity re-hashing and DB reparse replacement detection.

## 8. 5,000-file benchmark

Final delivery-container run:

| Metric | Result |
|---|---:|
| Corpus | 5,000 × 256 B |
| Cold scan | 5.280 s |
| Cold throughput | 946.89 files/s |
| Warm scan | 3.227 s |
| Warm throughput | 1,549.21 files/s |
| Warm hash-cache hits | 4,950 / 5,000 |
| Cold RSS end | ~120.4 MiB |
| Warm RSS end | ~124.5 MiB |
| Real-time fallback workload | 10 executable-like harmless files |
| Real-time fallback first pass | 1.635 s |
| Repeat pass (still re-scanned securely) | 1.620 s |

Why 4,950 rather than 5,000 warm cache hits: the benchmark corpus intentionally creates one `.cmd` every 100 files. Those 50 executable-like files are now deliberately re-hashed instead of trusting metadata cache.

`watchdog` is not installed in the delivery Linux container, so the real-time benchmark remains explicitly labelled `direct_pipeline_fallback`. The native Observer result must come from the Windows acceptance harness.

## 9. Roadmap update — macOS installer included

`ROADMAP.md` now contains a dedicated macOS track:

1. **v0.8 — macOS Native Protection Foundation**
   - platform-neutral detection contracts;
   - macOS-native process/file telemetry;
   - Endpoint Security evaluation/integration;
   - helper/daemon + authenticated IPC;
   - macOS permissions and recovery semantics.

2. **v0.9 — Production Packaging**
   - Windows signed installer;
   - signed macOS `.app`;
   - signed `.pkg` and/or polished `.dmg` distribution;
   - Developer ID signing;
   - Hardened Runtime;
   - notarization/stapling;
   - Gatekeeper validation;
   - clean install/update/uninstall/rollback testing.

The repository also contains `packaging/macos/README.md` as the explicit packaging gate. It intentionally refuses to present a Mac installer as complete before the native Mac protection backend exists.

## 10. Phase 1 freeze gate

v0.3.1 RC1 should be considered **code-complete for this iteration, not yet target-certified**.

Before freezing Phase 1:

1. run `tools.windows_acceptance` on the real Windows machine;
2. require native watchdog Observer PASS;
3. require ETW PASS;
4. inspect Authenticode result;
5. require NTFS junction/reparse PASS where supported;
6. archive benchmark JSON;
7. run normal application smoke test with real UI/DPI scaling;
8. perform quarantine/restore on harmless test files;
9. confirm no material false-positive regression on normal installed software.

Only after this gate should the roadmap move to v0.4 Reputation + Network Intelligence.
