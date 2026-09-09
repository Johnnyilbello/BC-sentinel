# BC Sentinel v0.3.1 RC1 — Adversarial Hardening & Acceptance

RC1 continues the v0.3.1 hardening line and specifically closes cache/metadata trust gaps discovered during review.

## Security changes

- Security-sensitive executable/script extensions are always content-hashed instead of trusting the persistent mtime+size hash cache.
- Real-time accepted executable events are no longer skipped for ten minutes solely because mtime+size match a prior observation; the existing event debounce remains in place to collapse event storms.
- Hash allowlist trust re-verifies current file bytes when the candidate digest came from metadata cache.
- Process identity enrichment hashes executable bytes for each new enrichment request off the ETW callback thread; only post-hash identity/signature data is reused.
- File reputation cache lookup is now bound to SHA-256 in addition to path/mtime/size.
- SQLite database, WAL and SHM paths are re-checked for symlink/reparse redirection on every connection.
- SQLite connections enable `foreign_keys`, `trusted_schema=OFF` and a consistent busy timeout.
- Quarantine snapshot comparison includes filesystem object identity (`st_dev`/`st_ino` where available), closing common same-size/same-mtime path-swap races.
- Additional Windows-risk extensions are covered by security-sensitive executable handling (`.sys`, `.ocx`, `.cpl`, `.hta`, `.jar`, `.lnk`).

## Acceptance tooling

Added `tools/windows_acceptance.py`, a safe target-machine gate that checks:

- required runtime modules;
- native watchdog filesystem Observer;
- ETW process/file providers;
- local Authenticode inspection;
- NTFS reparse/junction detection;
- timestamp-restoration cache evasion regression;
- scan and real-time benchmark output.

Run on the Windows target:

```text
python -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --output acceptance-v031-rc1.json
```

No real malware is required or used by this acceptance harness.

## Roadmap

Added `ROADMAP.md` with separate Windows and macOS tracks. macOS now explicitly includes a native protection foundation followed by signed/notarized `.app` + `.pkg`/`.dmg` installer delivery. A Mac installer will not be treated as complete until the macOS-native protection daemon/API entitlements and update path are valid.

## Final regression / benchmark

- `pytest`: **137 passed**.
- 5,000-file cold scan: **5.280 s / 946.89 files/s**.
- 5,000-file warm scan: **3.227 s / 1,549.21 files/s**.
- Warm hash cache: **4,950/5,000 hits**; the remaining 50 are `.cmd` files deliberately re-hashed for security.
- Native watchdog/ETW acceptance is still pending on the target Windows machine and is not falsely marked as validated in this container.
