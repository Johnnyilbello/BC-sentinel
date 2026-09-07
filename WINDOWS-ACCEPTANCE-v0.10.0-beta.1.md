# BC Sentinel v0.10.0-beta.1 — Native Windows Acceptance

Run from an elevated PowerShell in the extracted `BC-Sentinel` directory.

## 1. Environment and Python regression

```powershell
py -3.12 -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
& ".\.venv\Scripts\python.exe" -m pytest -q
```

Expected candidate baseline: all tests pass on Windows (the development environment has 491 passed + 1 Windows-only skipped, so Windows should execute that additional test).

## 2. Dedicated v0.10 acceptance

```powershell
& ".\.venv\Scripts\python.exe" -m tools.v010_web_deception_acceptance --output acceptance-v010-beta1-local.json
```

Require `"passed": true`.

## 3. Aggregate Windows foundation

```powershell
& ".\.venv\Scripts\python.exe" -m tools.windows_acceptance --output acceptance-v010-beta1-windows-foundation.json
```

Require zero critical failures, including `web-deception-v010-beta1-foundation` and frozen v0.9 gates.

## 4. Native build

```powershell
powershell -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
```

## 5. Upgrade from frozen v0.9 RC1

```powershell
& ".\.venv\Scripts\python.exe" -m tools.update_acceptance --mode upgrade --output acceptance-v010-beta1-update-plan.json
powershell -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Upgrade
```

## 6. Aggregate live-service acceptance

```powershell
& ".\.venv\Scripts\python.exe" -m tools.windows_acceptance --service-live --output acceptance-v010-beta1-windows-live.json
```

Require zero critical failures, including `web-deception-v010-beta1-live`.

## 7. Repair and hardening

```powershell
& ".\.venv\Scripts\python.exe" -m tools.update_acceptance --mode repair --output acceptance-v010-beta1-repair-plan.json
powershell -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Repair
& ".\.venv\Scripts\python.exe" -m tools.service_hardening_benchmark --output benchmark-v010-beta1-service-hardening.json
```

## 8. Post-reboot live validation

After reboot:

```powershell
& ".\.venv\Scripts\python.exe" -m tools.windows_acceptance --service-live --output acceptance-v010-beta1-post-reboot.json
```

A later version must not weaken the frozen v0.9 gates or the v0.10 heuristic safety cap merely to obtain a green acceptance result.
