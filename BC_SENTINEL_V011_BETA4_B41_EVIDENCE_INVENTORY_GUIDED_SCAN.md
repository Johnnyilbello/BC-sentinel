# BC Sentinel v0.11.0-beta.4 — B4-1 Evidence Inventory + Guided Scan

## Purpose
B4-1 integrates read-only evidence inventory and explicit RR-3 offline scanning into the Beta4 Rescue Console without granting any new mutation authority.

Frozen predecessor:

```text
checkpoint/v011-beta4-b40-pass
3bb5d0553397cccefba31eac70c09a99305e2492
```

B4-0 and all Beta3 checkpoints remain immutable.

## Trust model
Finding an evidence file is not enough to trust or reuse it.

B4-1 classifies evidence as:

- `TRUSTED`: required provenance/integrity checks currently match the target;
- `UNTRUSTED`: evidence exists but is stale, incomplete, malformed, unsafe or inconsistent;
- `MISSING`: expected evidence is absent.

An existing RR-3 scan can be reused only when all mandatory checks pass.

## Existing RR-3 scan verification
For reuse, B4-1 checks at minimum:

- RR-3 profile and offline-read-only mode;
- declared offline target matches the current target;
- scan completed without errors or max-file truncation;
- RR-3 safety contract still states no target writes/automatic action;
- hashed findings that can be revalidated still match current target bytes;
- mandatory `SYSTEM` and `SOFTWARE` hive hashes are present and still match current target bytes;
- scan evidence resides outside the offline target and is not a symlink/reparse artifact.

Any mismatch makes the scan `UNTRUSTED` for reuse.

## Guided scan execution
A fresh RR-3 scan is never launched merely because the Console starts.

Fresh scanning requires explicit operator invocation (`--run-scan`).

Trusted reuse requires explicit operator invocation (`--reuse-trusted-scan`) plus evidence that passes the inventory trust checks.

If reuse is requested for untrusted/missing evidence and no fresh scan was requested, the Console does not scan automatically. It returns:

```text
operator_action_required=run_fresh_scan
```

## Scan findings do not authorize repair
Even when RR-3 returns a deterministic IOC or YARA finding:

```text
repair_triggered=false
quarantine_triggered=false
automatic_execution=false
```

B4-1 does not invoke RR-4A/RR-4B. Guided repair handoff belongs to B4-2.

## Session audit
B4-1 writes structured JSONL audit events outside the target.

Critical events record:

- profile;
- session ID;
- correlation ID;
- target fingerprint;
- stage;
- status;
- reason;
- elapsed time;
- counters and normalized paths when relevant.

Stages include at least:

- evidence inventory start/end;
- offline scan start/end/failure or trusted reuse/refusal;
- guided scan completion.

## Output artifacts
Outside the offline target:

```text
b41-evidence-inventory.json
b41-guided-scan-summary.json
b41-audit.jsonl
rr3/rr3-offline-scan.json
rr3/rr3-audit.jsonl
```

RR-3 files exist only when a fresh scan was explicitly executed in that workspace.

## Safety boundary
B4-1 adds no authority for:

- repair execution;
- quarantine execution;
- process kill;
- host isolation;
- registry write;
- boot write;
- source/target file delete;
- target execution;
- automatic stage execution.

The offline target remains read-only.

## Acceptance gate
B4-1 Windows acceptance must prove:

1. Beta3 + B4-0 + B4-1 regression tests PASS;
2. all predecessor deterministic acceptance gates PASS;
3. B4-1 deterministic acceptance PASS;
4. fresh RR-3 scan runs only when explicitly requested;
5. deterministic IOC is observed without triggering repair/quarantine;
6. fresh scan becomes trusted reusable evidence;
7. trusted existing evidence can be reused without a second scan;
8. tampered/incomplete evidence is refused for reuse and requests a fresh scan;
9. structured audit includes stage/reason/timing/session/correlation context;
10. target remains byte-identical;
11. no Windows service is registered;
12. B2 protected service/realtime/EDR sources remain byte-identical.

Only after the Windows gate passes may B4-1 be frozen.
