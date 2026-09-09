# BC Sentinel v0.6.2-beta.3 — Release Notes

## Scope
Native Windows PowerShell parser-acceptance harness fix.

## Fixed
- The v0.6.2-beta.2 product script fix remains intact (`${Mode}:`).
- Fixed the Windows pytest parser acceptance itself: the path to `AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1` is now transported through a dedicated environment variable instead of being appended after `-Command`.
- This avoids tokenization failures on Windows user paths containing spaces, such as `C:\Users\LNV 83JG00B6IX\...`.
- Added a regression assertion preventing reintroduction of the `$args[0]`-after-`-Command` transport pattern.

## Security posture
No changes to the update transaction, privileged-ticket protocol, UAC broker, Named Pipe authentication, anti-replay, manifest verification, anti-downgrade, backup/rollback, ACL hardening, or v0.6.1 baseline.
