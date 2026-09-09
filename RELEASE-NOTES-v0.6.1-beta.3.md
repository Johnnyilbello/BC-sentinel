# BC Sentinel v0.6.1-beta.3

## ProgramData State ACL Recovery
This beta addresses the native Windows bootstrap failure observed after upgrading from earlier v0.6.1 beta ACL layouts.

### Fixed
- Repairs stranded ACLs on existing `ProgramData\BCSentinel\Protection` state before applying the final hardened ACL model.
- Replaces locale-dependent TAKEOWN recovery with SID-based `icacls /setowner` recovery.
- Repairs previous protected Program Files trees without manual ownership commands.
- Requires the Protection Service to remain `RUNNING` after bootstrap before installer success is reported.
- Prints Windows Application/SCM diagnostics automatically on bootstrap failure.
- Logs early `ProtectionRuntime` construction failures by constructing the runtime inside `SvcDoRun`.

### Preserved
- Program Files immutable deployment.
- Separate IPC token and machine-private integrity HMAC key.
- Authenticated SHA-256 integrity manifest.
- NTFS ChangeTime-backed incremental integrity cache and fail-safe rehash fallback.
- HMAC chained service audit.
- Named Pipe authenticated local IPC and remote-client rejection.
- Manual-only destructive response policy.

### Development verification
- 236/236 tests PASS.
- compileall PASS.
- Windows native acceptance pending.
