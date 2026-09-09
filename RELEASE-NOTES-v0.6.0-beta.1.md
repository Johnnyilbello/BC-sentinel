# BC Sentinel v0.6.0-beta.1 — Protection Service IPC Bootstrap Fix

## Field defect fixed
Windows native acceptance of v0.6.0-beta proved that the frozen Protection Service could be installed and remain RUNNING while its Named Pipe control plane was absent. The first manual PyInstaller build also proved that the original service build path did not include the local `sentinel` package unless the repository root was explicitly supplied.

## Fixes
- version bumped to `0.6.0-beta.1` (`0.6.0b2` package metadata);
- official Protection Service build now uses project-root `--paths` and `--collect-submodules sentinel`;
- dedicated `BUILD-SERVIZIO-PROTEZIONE.ps1` added;
- installer requires the frozen service host and no longer installs the fragile virtualenv `pythonservice.exe` path;
- frozen service runs `pipe-selftest` before SCM registration;
- first secured Named Pipe instance is created synchronously before the service reports IPC readiness;
- fatal IPC thread failure signals the service stop event instead of leaving a hollow RUNNING service;
- pipe security attributes are validated before use;
- Windows acceptance now includes `protection-pipe-create` to prove an actual secured pipe can be created, not merely that pywin32 imports exist.

## Validation in development environment
- pytest: 203 passed
- compileall: PASS

## Required Windows freeze
1. build service with `BUILD-SERVIZIO-PROTEZIONE.ps1`;
2. install with `INSTALLA-SERVIZIO-PROTEZIONE.ps1` as Administrator;
3. require `BCSentinelProtection` RUNNING;
4. run `tools.windows_acceptance --service-live`;
5. require both `protection-pipe-create=pass` and `protection-service-live=pass` with no critical failures.
