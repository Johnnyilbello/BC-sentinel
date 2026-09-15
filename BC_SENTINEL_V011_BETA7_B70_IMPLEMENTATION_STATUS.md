# BC Sentinel v0.11.0-beta.7 — B7-0 Implementation Status

Status: **IMPLEMENTED — WINDOWS CI IN PROGRESS / LOCAL WINDOWS ACCEPTANCE PENDING**

Active branch:

```text
feature/v011-beta7-b70-coverage-ledger
```

Frozen predecessor:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

## What B7-0 adds

B7-0 introduces the machine-readable attack coverage ledger required by the forward roadmap.

It does **not** add a detector, automatic response, repair authority or privileged execution path.

New components:

```text
BC_Sentinel_Roadmap_v0_11_0_Beta7.md
coverage/attack_coverage_ledger.json
sentinel/coverage_ledger.py
tests/test_v011_beta7_b70_coverage_ledger.py
.github/workflows/b70-coverage-ledger.yml
TEST-V011-BETA7-B70.ps1
```

The seed ledger contains six planned controlled scenario families:

- PowerShell/script abuse;
- Run Key/startup persistence;
- harmless ransomware-like behavior;
- security-control impairment/tampering;
- suspicious DNS/application-layer sequence;
- harmless credential-access indicators.

All six start as `PLANNED`. Therefore B7-0 makes **zero positive protection claims** for those scenarios.

## Semantic claim gate

A scenario may not claim positive coverage unless it includes:

- a non-empty `last_verified_build`;
- at least one evidence reference;
- non-`NONE` evidence quality;
- evaluated coverage fields.

`PLANNED` entries must remain unevaluated and cannot carry verification evidence.

Duplicate `scenario_id` values are rejected.

`VERIFIED` requires `detected = true` in addition to provenance/evidence.

`GAP` is also evidence-backed: a failure is recorded as an engineering fact rather than silently disappearing.

## B7-0 safety boundary

```text
read_only = true
execution_authority_added = false
automatic_quarantine = false
automatic_repair = false
automatic_restore = false
general_home_execution_authorized = false
```

Protected B2 sources remain frozen against the accepted Beta6 checkpoint.

## Acceptance gates

Windows CI runs:

1. compile check;
2. Beta5 + Beta6 predecessor regression;
3. B7-0 deterministic tests;
4. coverage ledger semantic self-check.

Local Windows acceptance uses:

```powershell
git fetch origin; git checkout feature/v011-beta7-b70-coverage-ledger; git pull --ff-only origin feature/v011-beta7-b70-coverage-ledger; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B70.ps1" -ConfirmCoverageLedgerAcceptance
```

Do not create `checkpoint/v011-beta7-b70-pass` until Windows CI and local acceptance both pass.
