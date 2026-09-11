# BC Sentinel — Roadmap v0.11.0-beta.4 Rescue Console

## Frozen predecessor
Beta4 starts only from the accepted Beta3 Rescue & Recovery checkpoint:

```text
checkpoint/v011-beta3-rr6-pass
e03482f4216c4cd20ede1e16d9a4c4b5b07668bc
```

RR-0 through RR-6 remain immutable predecessors. Beta4 must not weaken or bypass any accepted safety gate.

## Beta4 goal
Turn the independently accepted Rescue components into one coherent operator workflow for servicing an offline or compromised Windows installation, while preserving explicit operator control and all Beta3 trust boundaries.

Beta4 is orchestration, not a grant of new mutation authority.

## B4-0 — Rescue Console Orchestrator Foundation — accepted
Purpose: establish the session contract and deterministic workflow plan before any integrated execution is allowed.

Accepted scope:
- validated offline Windows target using the accepted RR-6 target contract;
- Rescue workspace only outside the target;
- deterministic target fingerprint, session ID and correlation ID;
- inventory of RR-1, RR-2, RR-3, RR-4A, RR-4B, RR-5 and RR-6 module availability;
- fixed stage order: target validation → evidence inventory → offline scan → repair review → safe data rescue → integrity certification;
- auditable session plan with SHA-256;
- operational stages remain `planned_only` and operator-gated;
- no automatic execution, repair, quarantine, kill, isolation, registry/boot write or delete;
- target remains byte-identical;
- reimage/format remains available when trust cannot be demonstrated.

Authoritative Windows acceptance:
- Beta3 + B4-0 regression: **144 tests PASS**;
- deterministic RR-0 through RR-6 + B4-0 acceptance PASS;
- live stage-order/module-inventory/operator-gate checks PASS;
- target unchanged, no service, B2 protected sources unchanged;
- final B4-0 core and bootstrap PASS.

Frozen checkpoint:

```text
checkpoint/v011-beta4-b40-pass
3bb5d0553397cccefba31eac70c09a99305e2492
```

This checkpoint is immutable.

## B4-1 — Evidence Inventory + Guided Scan — accepted
Accepted scope:
- evidence classified as `TRUSTED`, `UNTRUSTED` or `MISSING`;
- existing RR-3 evidence revalidated before reuse;
- target/profile/mode/safety contract, scan completeness, hashed findings and mandatory hive hashes checked;
- stale/incomplete/tampered evidence surfaced as untrusted with exact reasons;
- fresh RR-3 scan requires explicit operator request;
- trusted reuse requires explicit operator request;
- deterministic IOC/YARA findings do not automatically trigger repair or quarantine;
- target remains byte-identical;
- no new mutation authority added.

Authoritative Windows acceptance:
- Beta3 + B4-0 + B4-1 regression: **157 tests PASS**;
- all predecessor deterministic acceptances PASS;
- fresh RR-3 scan PASS;
- deterministic IOC observed without automatic action PASS;
- trusted scan reuse PASS;
- tampered scan refusal PASS;
- target unchanged, no service, B2 protected sources unchanged;
- final B4-1 core and bootstrap PASS.

Frozen checkpoint:

```text
checkpoint/v011-beta4-b41-pass
5049b2246df692c0f417131af44353cc234e1f95
```

This checkpoint is immutable.

## B4-2 — Guided Repair Handoff — current
Purpose: connect trusted B4-1 evidence to the already accepted RR-4B transaction engine without duplicating or broadening mutation authority inside the Console.

Required boundaries:
- a repair handoff requires `TRUSTED` RR-3 evidence;
- the operator-supplied RR-4B operations file must be explicitly approved;
- operations are bound to both the current RR-6 target fingerprint and the exact trusted RR-3 scan SHA-256;
- every operation retains an evidence reference;
- the Console may create the immutable RR-4B plan and expose its exact plan-bound confirmation token;
- the Console does **not** execute repair or rollback in B4-2;
- execution and rollback remain delegated to the frozen RR-4B engine and its already accepted confirmation/backup/precondition/rollback semantics;
- exact plan-bound confirmation remains mandatory in RR-4B;
- verified backup before mutation remains mandatory in RR-4B;
- stale plan/precondition refusal and rollback preflight remain mandatory in RR-4B;
- no heuristic-only repair;
- no confirmation may be synthesized or auto-approved;
- preparation of the handoff must leave the target byte-identical;
- no new mutation authority is added.

B4-2 Windows acceptance must include Beta3 + B4-0..B4-2 regression, all predecessor deterministic gates including RR-4B execute/rollback acceptance, deterministic B4-2 handoff acceptance, live trusted-scan/approved-operations binding, plan-bound confirmation generation, target unchanged, no service and B2 protected sources unchanged.

## B4-3 — Guided Safe Data Rescue
Integrate RR-5 explicit-selection rescue into the session.

Required boundaries:
- no blind whole-disk copy;
- active/ambiguous/IOC material remains contained;
- source remains read-only;
- SHA-256 verification remains mandatory;
- destination stays outside target.

## B4-4 — Integrated Certification + Session Summary
Invoke RR-6 only after all required evidence is available and produce one session-level outcome.

Allowed final states:
- `RECOVERED`;
- `NOT_RECOVERED`;
- `INDETERMINATE_REFUSED`.

The Console may not translate a refused/indeterminate certification into a success state.

## B4-5 — Portable Rescue Console
Package the accepted integrated workflow as a standard-user portable application/CLI without installer/service/driver requirements.

Acceptance must prove:
- built artifact integrity;
- no service registration;
- no new live-host mutation authority;
- Beta3 + B4 regression green;
- protected B2 service/realtime/EDR sources unchanged.

## Beta4 closure condition
Beta4 closes only after B4-0 through B4-5 pass deterministic and Windows built-artifact gates and the final accepted branch is frozen. No milestone may move forward merely to make the Console appear complete.

## Logging policy
Every critical failure must expose:
- stage;
- reason/cause;
- session and correlation ID when available;
- target fingerprint when safe/useful;
- component state;
- exit code for child processes;
- counters before/after when relevant;
- timings;
- normalized paths involved in the failed operation.

Production logs must remain structured and rate-limited; acceptance/diagnostic logs may be verbose.

## Codex reasoning policy
- **Extra High**: orchestration trust boundaries, transaction handoff, certification semantics and any capability that could mutate a target.
- **High**: implementation, tests and packaging after the corresponding boundary is frozen.
- milestone-by-milestone only.
