# BC Sentinel v0.6.1-beta.3 — ProgramData State ACL Recovery Report

## Native Windows finding
The v0.6.1-beta.2 installer successfully deployed the frozen Protection Service under `C:\Program Files\BC Sentinel\Protection`, sealed the integrity manifest, and passed the named-pipe self-test. The installed service nevertheless stopped during runtime bootstrap with Windows service-specific failure 1 / Win32 1066.

The same installer output exposed the root migration issue before service start:
- `C:\ProgramData\BCSentinel\Protection\quarantine.key: Accesso negato.`
- `C:\ProgramData\BCSentinel\Protection\sentinel-service.db: Accesso negato.`

Those objects were remnants of the previous v0.6.1 beta ACL layout. A normal child `/reset` was insufficient because the elevated installer no longer had an effective usable ACE on the stranded objects.

A second defect was also identified in the recovery path: `takeown.exe /D Y` is locale-dependent; on the tested Italian Windows build `Y` was rejected for `/D`.

## Fixes in beta.3
1. Added locale-neutral `Repair-TreeAclForAdministrators` using SID-based `icacls /setowner` and direct SYSTEM/Administrators Full Control grants.
2. Applied ACL recovery to both the Program Files deployment tree and the existing ProgramData Protection state tree before final lockdown.
3. Preserved the final hardened model: users do not inherit read access to DB/quarantine/integrity keys; the interactive installer user receives read access only to the IPC token.
4. Removed executable use of `takeown.exe` and the localized `/D Y` response.
5. Added a stable post-start gate: install is not reported successful unless SCM observes the service remaining `RUNNING` after bootstrap.
6. Added Application + Service Control Manager diagnostics on service-start failure.
7. Moved heavy `ProtectionRuntime`/IPC construction from the Windows service constructor into `SvcDoRun`, so pre-runtime construction failures are logged to the Windows Event Log instead of silently terminating the host.
8. Strengthened `protection-hardening-foundation` acceptance to require the new state recovery and diagnostics paths.

## Regression status
- 236/236 tests PASS
- `python -m compileall -q sentinel app tools packaging` PASS
- focused v0.6/v0.6.1 tests: 60/60 PASS
- no `takeown.exe` command remains in the installer
- no new TCP service transport, pickle deserialization, shell execution, or arbitrary command RPC introduced

## Windows acceptance status
Pending native Windows rerun. The required next gate is the 200-file `--service-live` acceptance. If green, proceed to 5000-file final, service hardening benchmark, and reboot persistence acceptance.
