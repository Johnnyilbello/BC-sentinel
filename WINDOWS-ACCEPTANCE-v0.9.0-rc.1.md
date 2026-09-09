# BC Sentinel v0.9.0-rc.1 — Native Windows Acceptance

Run from an elevated PowerShell in the extracted `BC-Sentinel` directory unless a step explicitly says otherwise.

## 1. Python regression + RC local gate

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m tools.v090_release_candidate_acceptance --output acceptance-v090-rc1-local.json
```

Expected: pytest green and RC acceptance `"passed": true`.

## 2. Native Windows foundation before deployment

```powershell
.\.venv\Scripts\python.exe -m tools.windows_acceptance --output acceptance-v090-rc1-windows-foundation.json
```

Expected: zero critical failures, including `release-v090-rc1-foundation`.

## 3. Build frozen Protection Service + Broker

```powershell
powershell -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
```

Expected final banner: `BUILD PROTECTION SERVICE + UAC BROKER + FIREWALL OK`.

## 4. Validate upgrade plan from the installed Beta3 service

```powershell
.\.venv\Scripts\python.exe -m tools.update_acceptance --mode upgrade --output acceptance-v090-rc1-update-plan.json
```

Expected: `"passed": true`, target version `0.9.0-rc.1`, no anti-downgrade/integrity error.

## 5. Apply protected transactional upgrade

```powershell
powershell -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Upgrade
```

Expected: service returns RUNNING and the script reports the verified transaction completed.

## 6. Aggregate live-service acceptance

```powershell
.\.venv\Scripts\python.exe -m tools.windows_acceptance --service-live --output acceptance-v090-rc1-windows-live.json
```

Expected: zero critical failures, including `release-v090-rc1-live`, Beta1/Beta2/Beta3 live gates, firewall, broker, ETW, hardening and Protection Service checks.

## 7. Same-version repair acceptance after RC1 is installed

```powershell
.\.venv\Scripts\python.exe -m tools.update_acceptance --mode repair --output acceptance-v090-rc1-repair-plan.json
powershell -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Repair
```

Expected: repair plan and protected repair both pass without changing the product version.

## 8. Reboot persistence gate

Before reboot:

```powershell
.\.venv\Scripts\python.exe -m tools.reboot_acceptance --arm --state acceptance-v090-rc1-reboot-state.json --output acceptance-v090-rc1-reboot-arm.json
```

Restart Windows. After reboot, return to the same extracted directory and run:

```powershell
.\.venv\Scripts\python.exe -m tools.reboot_acceptance --verify --state acceptance-v090-rc1-reboot-state.json --output acceptance-v090-rc1-reboot-verify.json
```

Expected: `"passed": true`, reboot detected, Protection Service healthy/degraded, Windows named-pipe transport active and hardening healthy.

## 9. Service hardening benchmark

```powershell
.\.venv\Scripts\python.exe -m tools.service_hardening_benchmark --output benchmark-v090-rc1-service-hardening.json
```

## Freeze rule

Do not declare v0.9 frozen if any critical aggregate Windows gate fails. Do not weaken or bypass a failing historical gate; diagnose and fix the regression, then re-run the complete aggregate acceptance.
