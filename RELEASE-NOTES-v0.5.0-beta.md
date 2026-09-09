# BC Sentinel v0.5.0 Beta — Incident Correlation & Manual Response Foundation

## Summary

v0.5.0 turns the existing telemetry and Behavioral Correlation Engine 2.0 output into persistent, explainable incidents and adds a deliberately conservative manual response foundation.

This is not an autonomous EDR response release. It is the safety boundary that must exist before privileged service-owned response can be introduced.

## Added

- `IncidentCorrelationEngine` for process/file/behavior/persistence/network convergence;
- stable/reused `BCI-*` incident identity;
- bounded incident timeline;
- strongest-evidence-per-family scoring;
- allowlist suppression and deterministic-evidence override;
- persistent incident store;
- recommended-action generation;
- Activity UI incident context;
- manual `Terminate process` and `Quarantine file` controls;
- `ResponseEngine` with explicit operator approval;
- PID-generation/path validation;
- critical-process and protected-Windows-path gates;
- encrypted quarantine delegation;
- incident response audit trail;
- deliberately unsupported network containment until the protected service phase;
- Windows acceptance probe for incident creation and fail-closed response auditing.

## Safety invariants

- no autonomous kill;
- no automatic firewall rule;
- no forced kill after graceful-termination timeout;
- no response to low-score/low-confidence incidents;
- no response to protected Windows processes/paths;
- no response to allowlisted file/process context unless deterministic evidence separately surfaces the incident;
- every attempted manual response is auditable.

## Development validation

- full test suite: **176/176 PASS**;
- Python `compileall`: **PASS**;
- Behavioral Correlation 2.0 synthetic probe: **PASS**;
- Incident Response Foundation synthetic probe: **PASS**.

A real PySide6 GUI runtime was not available inside the Linux development container, so final visual/runtime acceptance belongs to the target Windows PC where PySide6 is installed.

## Native Windows freeze command

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --output acceptance-v050-final.json
```

Require `passed=true` and an empty `critical_failures` list.

## Next phase

**v0.5.1 / v0.5.x — Windows Protection Service, authenticated IPC and tamper-resistance foundation.**
