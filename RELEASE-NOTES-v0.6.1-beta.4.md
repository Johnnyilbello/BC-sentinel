# BC Sentinel v0.6.1-beta.4 — State ACL Recovery + IPC Listener Resilience

## Why this beta exists

Native Windows testing of v0.6.1-beta.3 proved that the hardened service could install under Program Files and reach `RUNNING`, but the live IPC checks could later fail because the named-pipe listener disappeared. The same installation also showed legacy `quarantine.key` and `sentinel-service.db` ACLs still producing `Accesso negato` during migration.

## Fixes

- Added explicit recovery for runtime-critical ProgramData files before config/runtime bootstrap.
- Recovery is locale-neutral: `takeown` is applied only to explicit BC Sentinel paths and never uses a localized `/D` answer token.
- SYSTEM and Built-in Administrators regain Full Control on recovered state objects, then the normal hardened ACL model is re-applied.
- Installation now fails before service registration if `quarantine.key` or `sentinel-service.db` remain inaccessible.
- Named-pipe accept errors `ERROR_BROKEN_PIPE (109)`, `ERROR_NO_DATA (232)`, `ERROR_PIPE_NOT_CONNECTED (233)`, and `ERROR_OPERATION_ABORTED (995)` are treated as recoverable per-instance races.
- Eight consecutive transient accept failures are still promoted to a fatal transport error.
- The Windows service supervises/re-prepares the IPC listener up to five times before failing closed and allowing SCM recovery to take over.

## Security posture

No authorization gate was weakened. The Named Pipe remains local-only, authenticated, token-gated, and administrator-gated for privileged operations. Persistent IPC failure still stops the service; this beta only prevents a single client/pipe race from collapsing protection.

## Development acceptance

- 239/239 tests passed.
- `python -m compileall -q sentinel app tools packaging` passed.
- Native Windows acceptance remains required before freeze.
