# BC Sentinel v0.6.0-beta.1 — Windows Protection Service IPC Bootstrap Fix

## Trigger
Native Windows validation of v0.6.0-beta found one critical freeze blocker: `BCSentinelProtection` could be registered as RUNNING while `\\.\pipe\BCSentinelProtection-v1` did not exist. The live acceptance failed with `WaitNamedPipe` error 2.

A second packaging defect was proven during field recovery: a manually frozen service built from `packaging/protection_service_entry.py` without repository-root search paths failed with `ModuleNotFoundError: sentinel`.

## Root architectural issue
The v0.6.0 service started the Named Pipe server only in a daemon thread after engine initialization. An unhandled exception in that thread did not terminate the Windows Service or change SCM state, allowing a false RUNNING state with no usable IPC control plane.

## Corrections
- synchronous first-pipe creation via `WindowsNamedPipeServer.prepare()`;
- explicit ready/fatal-error state on the pipe server;
- service bootstrap refuses to remain active if IPC bootstrap fails;
- fatal pipe-thread errors are logged and signal service shutdown;
- documented/validated SECURITY_ATTRIBUTES construction for the pipe DACL;
- pipe self-test command added to the frozen service entrypoint;
- installer runs the frozen `pipe-selftest` before service registration;
- dev `pythonservice.exe` fallback removed from normal v0.6.0-beta.1 installation;
- official PyInstaller configuration now includes the project root, all `sentinel` submodules and required pywin32 modules;
- dedicated service-only build script added;
- Windows acceptance gains `protection-pipe-create`.

## Regression result
- 203 / 203 tests PASS
- Python compileall PASS

## Security properties preserved
- Named Pipe remains local-only;
- existing SDDL keeps LocalSystem/Administrators full access and Authenticated Users read/write connection rights;
- command authorization, install secret and admin mutation gate remain unchanged;
- no TCP control server, pickle deserialization or generic command execution was introduced.

## Freeze status
DEVELOPMENT FIX COMPLETE. Native Windows `--service-live` acceptance remains required before v0.6.0-beta.1 can be frozen.
