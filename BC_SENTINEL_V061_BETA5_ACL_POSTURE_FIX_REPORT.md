# BC Sentinel v0.6.1-beta.5 — ACL Posture Fix Report

## Trigger
Native Windows beta.4 acceptance reached the Protection Service and Named Pipe successfully, but `protection-hardening-live` failed because `windows_acl_posture()` referenced an undefined `TRUSTED_WRITE_SIDS`. The service correctly degraded instead of reporting a sealed hardening posture.

## Root cause
The ACL inspection implementation was completed before the trusted-principal constant was actually declared in `sentinel/service_hardening.py`. Unit coverage only asserted that the identifier appeared in source, so the missing runtime binding escaped development tests.

## Fix
`TRUSTED_WRITE_SIDS` is now explicitly defined as:

- `S-1-5-18` — LocalSystem
- `S-1-5-32-544` — BUILTIN\Administrators

Per-service SIDs `S-1-5-80-*` continue to be handled by the existing explicit check. Standard Users, Authenticated Users and Everyone are intentionally not trusted writers.

Regression tests now import and validate the actual constant, and the Windows acceptance hardening-foundation check requires the constant and both trusted SIDs to be present.

## Development validation
- 242/242 tests PASS
- compileall PASS
- no Service/IPC architecture changes
- native Windows live hardening gate pending
