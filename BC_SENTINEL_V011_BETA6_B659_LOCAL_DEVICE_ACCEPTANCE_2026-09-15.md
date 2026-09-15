# BC Sentinel v0.11.0-beta.6 — B6-5.9 Local Windows Device Acceptance

Date: **2026-09-15**

Branch tested:

```text
feature/v011-beta6-b659-quarantine-integrity
```

Accepted code commit:

```text
72c18bbdf1c50c633343750ead0f2467d8705e12
```

Checkpoint created from the exact tested commit:

```text
checkpoint/v011-beta6-b659-pass
```

## Command used

```powershell
git fetch origin; git checkout feature/v011-beta6-b659-quarantine-integrity; git pull --ff-only origin feature/v011-beta6-b659-quarantine-integrity; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA6-B659.ps1" -ConfirmQuarantineIntegrityAcceptance -OpenUI
```

## Result

```text
B6-5.9 LOCAL WINDOWS DEVICE ACCEPTANCE: PASS
```

### Deterministic gate

```text
11 passed in 0.75s
Deterministic gate: PASS
```

### Fresh-process integrity visibility acceptance

```text
passed = true
fresh_process_verified = true
verified_row_visible = true
blocked_integrity_row_visible = true
blocked_restore_refused = true
blocked_target_not_restored = true
restart_discovery_read_only = true
valid_restore_verified = true
valid_sha256_identical = true
```

Safety invariants remained closed:

```text
general_home_execution_authorized = false
automatic_cleanup = false
automatic_quarantine = false
delete_authorized = false
repair_authorized = false
```

### Self-check

```text
Self-check B6-5.9: PASS
```

### Real UI preflight / launch

The B6-5.9 launcher completed the historical-runtime preflight, opened the real PySide6 UI, and terminated the UI session normally:

```text
UI B6-5.9 pronta.
Quarantene verificate: Ripristina file resta disponibile dopo verifica persistente.
Stati persistenti degradati: Verifica richiesta / Ripristino bloccato, senza pulsante di restore.
Discovery e audit restano read-only; nessun cleanup automatico.
Nessuna nuova autorita: DELETE e REPAIR restano disabilitati.
Sessione UI B6-5.9 terminata correttamente.
```

## Acceptance conclusion

B6-5.9 is accepted on the local Windows device. The tested build verifies both sides of the persistent quarantine state after a fresh process starts:

```text
Verified persistent quarantine
  -> visible
  -> explicit restore remains available
  -> restored SHA-256 identical to original

Degraded persistent quarantine
  -> visible as Verifica richiesta
  -> Ripristino bloccato
  -> no restore key / no restore action
  -> no automatic cleanup or restore
```

No broad remediation authority was introduced. Automatic cleanup/quarantine/restore/repair, DELETE, REPAIR, process termination, trust/allowlist mutation and privileged/system-file mutation remain outside the accepted authority boundary.
