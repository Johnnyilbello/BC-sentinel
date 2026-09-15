# BC Sentinel v0.11.0-beta.6 — B6-5.8 Local Windows Device Acceptance

Date: **2026-09-15**

Branch tested:

```text
feature/v011-beta6-b65-guided-resolution
```

Accepted code commit:

```text
643cbd46a6d196c1d4379ba5d6992dee328c14f1
```

Checkpoint created from the exact tested commit:

```text
checkpoint/v011-beta6-b658-pass
```

## Command used

```powershell
git fetch origin; git checkout feature/v011-beta6-b65-guided-resolution; git pull --ff-only origin feature/v011-beta6-b65-guided-resolution; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA6-B658.ps1" -ConfirmPersistentRestoreAcceptance -OpenUI
```

## Result

```text
B6-5.8 LOCAL WINDOWS DEVICE ACCEPTANCE: PASS
```

### Deterministic gate

```text
9 passed in 0.70s
Deterministic gate: PASS
```

### Fresh-process persistent restore acceptance

```text
passed = true
fresh_process_restart_verified = true
persistent_active_after_restart = true
persistent_restore_verified = true
quarantine_page_row_after_restart = true
recovery_record_created_before_restart = true
restart_discovery_read_only = true
restored_sha256_identical = true
rows_cleared_after_restore = true
```

Safety invariants remained closed:

```text
general_home_execution_authorized = false
automatic_quarantine = false
delete_authorized = false
repair_authorized = false
```

### Self-check

```text
Self-check B6-5.8: PASS
```

### Real UI preflight / launch

The B6-5.8 launcher completed the historical-runtime preflight, opened the real PySide6 UI, and terminated the UI session normally:

```text
UI B6-5.8 pronta.
Le quarantene verificate sopravvivono alla chiusura dell'app e compaiono nella pagina Quarantena.
Ripristina file ricontrolla record persistente, journal, snapshot e SHA-256 prima di intervenire.
Nessuna azione automatica; DELETE e REPAIR restano disabilitati.
Sessione UI B6-5.8 terminata correttamente.
```

## Acceptance conclusion

B6-5.8 is accepted on the local Windows device. The tested build verifies the complete restart-safe reversible lifecycle:

```text
Process A
  explicit user-mediated quarantine
  -> durable recovery record + hash-chained journal
  -> process exit

Process B
  fresh process
  -> read-only persistent discovery
  -> active Quarantine row reconstructed
  -> explicit restore
  -> restored SHA-256 identical to the original
```

No broad remediation authority was introduced. Automatic quarantine/restore/repair, DELETE, REPAIR, process termination, trust/allowlist mutation and privileged/system-file mutation remain outside the accepted authority boundary.
