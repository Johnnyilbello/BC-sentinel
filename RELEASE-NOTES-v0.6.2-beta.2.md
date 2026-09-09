# BC Sentinel v0.6.2-beta.2 — Release Notes

## Scope
Parser-safe transactional upgrade/repair script fix.

## Fixed
- Fixed Windows PowerShell parser error caused by interpolating `$Mode:` inside a double-quoted string.
- The update banner now uses `${Mode}:`, which is unambiguous to Windows PowerShell.
- No upgrade transaction is started before validation succeeds; the reported user failure occurred before service stop or filesystem replacement.
- Added a native-Windows parser acceptance test using `[scriptblock]::Create(...)`.
- Added a static regression assertion forbidding the unsafe `$Mode:` interpolation form.

## Security posture
No changes to the privileged-ticket protocol, UAC broker, named-pipe authentication, anti-replay, manifest verification, anti-downgrade, backup, rollback, or v0.6.1 hardening baseline.
