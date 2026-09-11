# BC Sentinel v0.11.0-beta.4 — B4-5 Portable Rescue Console

## Purpose
Package the accepted Beta4 Rescue Console workflow into one standard-user portable CLI while preserving every previously accepted trust and operator-control boundary.

B4-5 is packaging and dispatch. It does not create a second implementation of scanning, repair planning, data rescue or certification.

## Portable command surface
The executable exposes:

- `status` — read-only portable build/safety contract.
- `plan` — delegates to B4-0 Rescue Console session planning.
- `scan` — delegates to B4-1 trusted evidence inventory / explicit RR-3 scan.
- `repair-handoff` — delegates to B4-2 RR-4B plan/token handoff only.
- `data-rescue` — delegates to B4-3 explicit-selection RR-5 rescue.
- `certify` — delegates to B4-4 integrated session validation and frozen RR-6 certification.

There is intentionally **no `repair-execute` command**. Repair execution and rollback remain separate RR-4B operations with the exact plan-bound confirmation, verified backup, stale-precondition refusal and rollback preflight already frozen in Beta3.

## Safety contract
B4-5 must preserve:

- no installer requirement;
- no Windows service installation;
- no driver installation;
- no automatic repair;
- no automatic quarantine;
- no automatic destructive action;
- no network or cloud requirement;
- B4-3 explicit data-rescue execution semantics;
- B4-4/RR-6 exact `RECOVERED`, `NOT_RECOVERED`, `INDETERMINATE_REFUSED` outcomes;
- format/reimage remains available whenever integrity cannot be demonstrated;
- protected B2 service/realtime/EDR sources remain byte-identical.

## Packaging
PyInstaller `onedir` is used. The build reuses the hardened Windows strategy validated during RR-6:

- short build base under `%USERPROFILE%\BCSBuild\b45`;
- isolated work/spec/TEMP directories per attempt;
- maximum three attempts;
- captured native stderr without Windows PowerShell 5.1 converting normal PyInstaller diagnostics into a terminating error;
- classification/logging of Windows resource update failures, WinError 122 and access/lock failures;
- no antivirus/security-control disabling as a build requirement.

Expected output:

```text
dist\Rescue\BC-Sentinel-Rescue-Console-Portable\
  BC-Sentinel-Rescue-Console-Portable.exe
  rescue-console-integrity.json
  _internal\...
```

The integrity manifest records the executable SHA-256 and the safety/packaging contract.

## Acceptance
B4-5 is accepted only if all of the following pass on Windows from normal non-elevated PowerShell:

1. Beta3 + B4-0..B4-5 pytest regression: expected **198 passed**.
2. Deterministic RR-0..RR-6 and B4-0..B4-5 acceptance PASS.
3. Hardened PyInstaller build PASS.
4. `rescue-console-integrity.json` SHA-256 equals the built EXE SHA-256.
5. Built `status` reports profile `v0.11.0-beta.4-b45`, the exact accepted command surface, and no install/service/driver/automatic-repair authority.
6. Built `repair-execute` returns refusal and is not exposed as a supported command.
7. Built `scan`, `repair-handoff`, `data-rescue`, and `certify` parsers load successfully.
8. Built `plan` succeeds on a validated synthetic offline Windows target.
9. Built `scan --run-scan` succeeds and remains read-only.
10. Built `certify` on a clean trusted synthetic session returns `RECOVERED` and invokes RR-6.
11. Synthetic target remains byte-identical after the built-artifact flow.
12. No Windows service is registered by the portable console.
13. Protected B2 sources remain unchanged.
14. Final core and bootstrap report PASS.

Any failure blocks Beta4 closure. Acceptance thresholds may not be weakened to force PASS.

## Freeze rule
After authoritative Windows acceptance, freeze the exact tested commit as:

```text
checkpoint/v011-beta4-b45-pass
<exact accepted commit>
```

The checkpoint is immutable and must never move.
