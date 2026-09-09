# BC Sentinel v0.6.1-beta.4 — State ACL + IPC Recovery Report

## Native failure addressed

The v0.6.1-beta.3 installer reached `RUNNING` under `LocalSystem` and Program Files, but Windows acceptance subsequently reported `WaitNamedPipe: file not found`. Installer output also showed repeated access-denied errors for `C:\ProgramData\BCSentinel\Protection\quarantine.key` and `sentinel-service.db`.

## Root causes addressed

### 1. Legacy ProgramData ACL recovery was too generic
`icacls /setowner ... /T /C` could continue past inaccessible protected files without actually repairing the exact runtime-critical objects. Beta.4 performs explicit ownership recovery on known BC Sentinel state files, then reapplies deterministic SID-based ACLs and verifies critical objects are queryable before `init-config` and service registration.

### 2. Named-pipe accept loop was too brittle
The listener previously treated any `ConnectNamedPipe` error other than `ERROR_PIPE_CONNECTED` as fatal. Windows documents `ERROR_NO_DATA` as possible when a previous client has closed an instance. Beta.4 recycles known transient per-instance errors and applies a bounded retry budget; repeated failures remain fatal.

## Files changed

- `INSTALLA-SERVIZIO-PROTEZIONE.ps1`
- `sentinel/protection_transport_windows.py`
- `sentinel/protection_service_windows.py`
- `sentinel/config.py`
- `sentinel/__init__.py`
- `pyproject.toml`
- `tools/windows_acceptance.py`
- `tests/test_v060_protection_service.py`
- `tests/test_v061_service_hardening.py`
- `README.md`

## Development result

- 239/239 tests PASS
- compileall PASS
- Native Windows service-live/hardening-live still pending
