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

## B4-0 — Rescue Console Orchestrator Foundation — current
Purpose: establish the session contract and deterministic workflow plan before any integrated execution is allowed.

Scope:
- validate the offline Windows target using the accepted RR-6 target contract;
- create the Rescue workspace only outside the target;
- derive deterministic target fingerprint, session ID and correlation ID;
- inventory availability of RR-1, RR-2, RR-3, RR-4A, RR-4B, RR-5 and RR-6 modules;
- define the fixed stage order:
  1. target validation;
  2. evidence inventory;
  3. offline scan;
  4. repair review;
  5. safe data rescue;
  6. integrity certification;
- generate an auditable session plan with SHA-256;
- keep operational stages `planned_only` and operator-gated;
- no automatic execution, repair, quarantine, kill, isolation, registry/boot write or delete;
- target remains byte-identical;
- reimage/format remains available when trust cannot be demonstrated.

B4-0 Windows acceptance must include Beta3 regression, deterministic B4-0 acceptance and a live synthetic offline-target planning gate.

## B4-1 — Evidence Inventory + Guided Scan
Integrate read-only evidence discovery and RR-3 invocation into the Console.

Required boundaries:
- no scan result may automatically trigger repair;
- existing evidence must be provenance-checked before reuse;
- stale/incomplete evidence is surfaced as untrusted;
- scan remains offline/read-only;
- session audit records stage start/end, timings, counts and exact reason on failure.

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
