# BC Sentinel v0.7.0-beta.3 — Firewall Acceptance Canonicalization Fix

## Scope

Narrow corrective release for the native Windows Beta 2 acceptance false negative. Firewall enforcement, UAC broker authorization, global Windows Firewall policy boundaries and the transactional updater security model are unchanged.

## Native Beta 2 finding

The standard-user → UAC broker → Protection Service path successfully created the requested BLOCK rule and later removed it, but `tools.firewall_acceptance` reported `present_after_add=false`. The observed rule had the correct logical `BCSF-*` id, managed group, outbound direction and enabled state. Windows COM returned the host address as `192.0.2.77/255.255.255.255` while the acceptance probe expected the raw string `192.0.2.77`. Those representations are semantically identical IPv4 `/32` networks.

## Fixes

- Firewall acceptance canonicalizes single IPv4/IPv6 network representations with `ipaddress` before comparison.
- `192.0.2.77`, `192.0.2.77/32` and `192.0.2.77/255.255.255.255` are treated as the same endpoint.
- The probe still resolves the rule primarily by the exact logical `BCSF-*` id and additionally requires the exact BC Sentinel managed group, outbound direction, ANY protocol, no port/application widening and enabled state.
- Transactional `finally` cleanup, polling and baseline restoration from Beta 2 remain intact.
- Version advances to `0.7.0-beta.3`, enabling a real transactional upgrade from an installed `0.7.0-beta.2`.
- Same-version `upgrade` remains rejected; same-version validation uses `repair`.
- Downgrades remain rejected.
- `tools.update_acceptance` now classifies a same-version upgrade rejection and recommends `repair` without weakening the gate.

## Development verification

- pytest: `302 passed, 1 skipped` on non-Windows development host.
- skipped test: native Windows PowerShell parser gate.
- expected native Windows total: `303 passed`.
- `python -m compileall -q sentinel app tools packaging`: PASS.

## Native Windows acceptance sequence

From the extracted Beta 3 source tree:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1

# Elevated PowerShell: installed Beta 2 -> source Beta 3 must be a real upgrade.
.\.venv\Scripts\python.exe -m tools.update_acceptance --mode upgrade --output acceptance-v070-beta3-update-plan.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1 -Mode Upgrade

# Standard/non-elevated PowerShell: real broker + firewall mutation acceptance.
.\.venv\Scripts\python.exe -m tools.firewall_acceptance --output acceptance-v070-beta3-firewall.json
```

Release gate: `tools.update_acceptance` must report `passed=true` for Beta 2 → Beta 3, and `tools.firewall_acceptance` must report `present_after_add=true`, `absent_after_remove=true`, `baseline_restored=true`, and final `passed=true`.
