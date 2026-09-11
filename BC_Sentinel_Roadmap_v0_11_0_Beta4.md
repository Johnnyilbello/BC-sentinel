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

## B4-1 — Evidence Inventory + Guided Scan — current
Integrate read-only evidence discovery and RR-3 invocation into the Console.

Required boundaries:
- finding an evidence file does not make it trusted;
- existing RR-3 evidence must be provenance/integrity checked before reuse;
- evidence is classified as `TRUSTED`, `UNTRUSTED` or `MISSING`;
- target/profile/mode/safety contract, scan completeness, hashed findings and mandatory hive hashes are revalidated where applicable;
- stale/incomplete/tampered evidence is surfaced as untrusted with exact reasons;
- trusted evidence reuse requires explicit operator request;
- fresh RR-3 scan requires explicit operator request;
- an untrusted reuse request must not silently start a scan; it requests a fresh scan instead;
- scan remains offline/read-only and writes only outside target;
- deterministic IOC/YARA findings do not automatically trigger repair or quarantine;
- session audit records stage start/end, timings, counts, normalized paths and exact reason on failure;
- target remains byte-identical;
- no new mutation authority is added.

B4-1 Windows acceptance must include Beta3 + B4-0 + B4-1 regression, all predecessor deterministic gates, deterministic B4-1 acceptance, fresh-scan live gate, trusted-reuse live gate, tampered-evidence refusal, target unchanged, no service and B2 protected sources unchanged.

## B4-2 — Guided Repair Handoff
Integrate RR-4B plan/confirmation/execute/rollback without bypassing its accepted transaction semantics.

Required boundaries:
- exact plan-bound confirmation remains mandatory;
- verified backup before mutation remains mandatory;
- no heuristic-only repair;
- stale plan/precondition refuses execution;
- rollback preflight remains mandatory;
- Console cannot silently synthesize or auto-approve confirmations.

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
