# BC Sentinel v0.11.0-beta.4 — B4-0 Rescue Console Orchestrator Foundation

## Purpose
B4-0 is the first integration layer above the accepted Beta3 Rescue & Recovery engines. It creates a deterministic operator session plan but does not execute scan, repair, data rescue or certification automatically.

## Frozen predecessor
```text
checkpoint/v011-beta3-rr6-pass
e03482f4216c4cd20ede1e16d9a4c4b5b07668bc
```

The predecessor checkpoint is immutable.

## Profile
```text
v0.11.0-beta.4-b40
```

Plan schema:
```text
bc-sentinel-beta4-rescue-console-plan-v1
```

## Fixed stage order
1. `target_validation`
2. `evidence_inventory`
3. `offline_scan`
4. `repair_review`
5. `safe_data_rescue`
6. `integrity_certification`

B4-0 executes only validation/inventory planning logic. Operational stages are `planned_only`, require an operator gate, and have `automatic_execution=false`.

## Session identity
A validated offline Windows target is bound to:
- RR-6 deterministic target fingerprint;
- `B40-<fingerprint prefix>` session ID;
- deterministic correlation ID;
- SHA-256 of the stable session-plan core.

Workspace and output plan must be outside the target.

## Safety boundary
B4-0 adds no new mutation authority.

Mandatory flags:
- target read-only;
- no automatic execution;
- no automatic repair;
- no automatic quarantine;
- no process kill;
- no host isolation;
- no registry write;
- no boot write;
- no file delete;
- reimage/format is not suppressed.

B4-0 must never synthesize RR-4 confirmation tokens or perform a repair transaction.

## Module inventory
The session plan verifies availability of:
- RR-1 Portable;
- RR-2 Rescue USB;
- RR-3 Offline Scanner;
- RR-4A Repair Transaction Core;
- RR-4B Portable Repair Engine;
- RR-5 Safe Data Rescue;
- RR-6 Integrity Certification.

Missing modules are visible in the plan and may not be silently ignored by future integration milestones.

## Acceptance gate
Windows B4-0 acceptance requires:
- non-elevated PowerShell;
- compileall PASS;
- RR-0..RR-6 + B4-0 pytest regression PASS;
- RR-0..RR-6 deterministic acceptance PASS;
- B4-0 deterministic acceptance PASS;
- synthetic live offline Windows target planning PASS;
- exact stage order PASS;
- complete module inventory PASS;
- all planned-only stages operator-gated;
- no automatic execution/repair/quarantine;
- target unchanged;
- no Windows service registered;
- B2 protected service/realtime/EDR sources unchanged.

## Logging
Any failure must identify at least:
- stage;
- reason;
- relevant path or component;
- child-process exit code where applicable.

Session/correlation IDs and target fingerprint are emitted when planning succeeds.

## Transition to B4-1
B4-1 may integrate evidence inventory and explicit RR-3 scan invocation only after B4-0 is accepted and frozen. It may not pull forward repair execution or any new automatic action.
