# BC Sentinel v0.11.0-beta.4 — B4-2 Guided Repair Handoff

## Goal
B4-2 connects the trusted evidence produced by B4-1 to the accepted RR-4B repair transaction engine without granting the Rescue Console any new mutation authority.

The Console prepares a verified handoff. RR-4B remains the only component responsible for repair execution and rollback.

## Profile

```text
v0.11.0-beta.4-b42
```

## Frozen predecessor

```text
checkpoint/v011-beta4-b41-pass
5049b2246df692c0f417131af44353cc234e1f95
```

B4-1 and every earlier checkpoint remain immutable.

## Handoff trust requirements
A B4-2 handoff is prepared only when all of the following are true:

1. the target is a validated offline Windows root;
2. the Rescue workspace is outside the target;
3. RR-3 evidence is classified `TRUSTED` by B4-1 revalidation;
4. the RR-4B operations document uses the accepted `bc-sentinel-rr4b-operations-v1` schema;
5. the operations document is explicitly `approved: true`;
6. its `target_fingerprint` exactly matches the current RR-6 target fingerprint;
7. its `source_scan_sha256` exactly matches the trusted RR-3 scan;
8. every operation has an evidence reference;
9. RR-4B itself accepts target pre-state hashes and replacement provenance while creating the plan.

Missing, stale, tampered or incorrectly bound evidence is refused.

## Console authority boundary
B4-2 may:

- validate trusted evidence;
- validate the operator-approved operations binding;
- ask RR-4B to create an immutable repair plan;
- expose the RR-4B plan SHA-256;
- expose the exact plan-bound confirmation token;
- write the handoff manifest and structured audit outside the target.

B4-2 may **not**:

- execute a repair;
- execute rollback;
- auto-approve a confirmation;
- synthesize an operator confirmation;
- turn heuristic findings into repair operations;
- delete files;
- write registry or boot state;
- kill processes or isolate the host;
- certify recovery.

## RR-4B remains authoritative for mutation
The accepted RR-4B engine retains the mutation contract:

- exact confirmation token bound to plan SHA-256;
- target fingerprint and pre-state validation;
- replacement-source provenance validation;
- verified backup before each write;
- verified post-state after each write;
- automatic rollback of already-applied operations on transaction failure;
- manual rollback only after post-state and backup provenance preflight;
- no recovery certification from repair alone.

B4-2 does not reimplement or weaken these semantics.

## Output
The Console writes:

```text
b42-repair-handoff.json
b42-audit.jsonl
rr4b/repair-plan.json
```

The handoff records:

- profile;
- session ID;
- correlation ID;
- target fingerprint;
- trusted scan path and SHA-256;
- operator operations path;
- operation count;
- RR-4B plan path and SHA-256;
- exact confirmation token;
- explicit confirmation-required flag;
- explicit zero-execution/zero-rollback flags;
- delegation flags for RR-4B execution and rollback.

## Acceptance
B4-2 is accepted only if Windows gates prove:

- Beta3 + B4-0 + B4-1 + B4-2 regression green;
- all predecessor deterministic acceptances green;
- RR-4B execute/rollback acceptance still green;
- trusted scan binding PASS;
- target fingerprint binding PASS;
- scan SHA-256 binding PASS;
- explicit operations approval PASS;
- RR-4B plan creation PASS;
- exact plan-bound confirmation token PASS;
- tampered/untrusted scan refusal PASS;
- unbound operations refusal PASS;
- Console performs no repair during handoff preparation;
- target byte-identical after handoff preparation;
- no Windows service registered;
- protected B2 service/realtime/EDR sources unchanged.

Expected final gates:

```text
B42 LIVE: trusted scan binding PASS | approved operations binding PASS | plan-bound confirmation PASS | RR4B regression execute/rollback PASS | no console auto-repair | target unchanged | no service | B2 sources unchanged
BC SENTINEL v0.11.0-beta.4 B4-2 GUIDED REPAIR HANDOFF - PASS
BC SENTINEL v0.11.0-beta.4 B4-2 BOOTSTRAP - PASS
```

## Safety conclusion
B4-2 is an orchestration and trust-binding milestone. It deliberately avoids adding a second repair executor to the product. The accepted RR-4B transaction engine remains the sole repair/rollback authority until a later milestone explicitly changes that boundary and passes a new acceptance gate.
