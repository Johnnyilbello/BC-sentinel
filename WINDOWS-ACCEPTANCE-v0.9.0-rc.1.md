# BC Sentinel v0.9.0-rc.1 — Native Windows Acceptance

The full matrix below was completed successfully on the target Windows machine on 2026-09-07.

## 1. Python regression + RC local gate

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m tools.v090_release_candidate_acceptance --output acceptance-v090-rc1-local.json
```

Final result: **482/482 PASS**, RC acceptance `passed: true`.

## 2. Native Windows foundation

```powershell
.\.venv\Scripts\python.exe -m tools.windows_acceptance --output acceptance-v090-rc1-windows-foundation.json
```

Final result: **PASS**, zero critical failures.

## 3. Build frozen Protection Service + Broker

```powershell
powershell -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
```

Final result: **PASS**.

## 4. Upgrade acceptance + protected upgrade

```powershell
.\.venv\Scripts\python.exe -m tools.update_acceptance --mode upgrade --output acceptance-v090-rc1-update-plan.json
powershell -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Upgrade
```

Final result: **PASS**.

## 5. Aggregate live-service acceptance

```powershell
.\.venv\Scripts\python.exe -m tools.windows_acceptance --service-live --output acceptance-v090-rc1-windows-live.json
```

Final result: **PASS**, zero critical failures.

## 6. Same-version repair

```powershell
.\.venv\Scripts\python.exe -m tools.update_acceptance --mode repair --output acceptance-v090-rc1-repair-plan.json
powershell -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Repair
```

Final result: **PASS**.

## 7. Reboot/live persistence

The protected installation was revalidated after reboot with the aggregate live-service gate. Final result: **PASS**.

## 8. Service-hardening benchmark

```powershell
.\.venv\Scripts\python.exe -m tools.service_hardening_benchmark --output benchmark-v090-rc1-service-hardening.json
```

Final result: **PASS**.

## Freeze rule

The v0.9 RC1 gates are now frozen regression requirements. Do not weaken or bypass a historical gate to make a later version pass; diagnose the regression and rerun the complete aggregate acceptance.
