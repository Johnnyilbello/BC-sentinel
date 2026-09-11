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

## B4-1 — Evidence Inventory + Guided Scan — accepted
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

## B4-2 — Guided Repair Handoff — accepted
Accepted boundary:
- trusted B4-1 scan required;
- operator-supplied RR-4B operations must be explicitly approved;
- operations bound to current target fingerprint and exact trusted scan SHA-256;
- Console creates RR-4B plan and exposes exact plan-bound confirmation token;
- Console does not execute repair or rollback;
- mutation remains delegated to frozen RR-4B semantics;
- exact confirmation, verified backup, stale-precondition refusal and rollback preflight remain mandatory;
- target remains byte-identical during handoff preparation;
- no new mutation authority added.

Authoritative Windows acceptance:
- Beta3 + B4-0..B4-2 regression: **167 tests PASS**;
- all predecessor deterministic acceptances PASS;
- RR-4B execute/rollback regression PASS;
- trusted scan binding PASS;
- approved operations binding PASS;
- plan-bound confirmation PASS;
- no Console auto-repair;
- target unchanged, no service, B2 protected sources unchanged;
- final B4-2 core and bootstrap PASS.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b42-pass
cb6ef6dd65ed9528c4613f896e0c84fde66ffc79
```

## B4-3 — Guided Safe Data Rescue — current
Purpose: integrate the accepted RR-5 explicit-selection data rescue into the Console without turning data recovery into an automatic or blind copy path.

Required boundaries:
- B4-3 requires trusted RR-3 evidence from B4-1;
- data selections must be explicit and remain restricted to RR-5 accepted `Users/<profile>` scope;
- preview and execution are separate: preview creates only a rescue plan and never copies data;
- actual copying requires an explicit operator execution request;
- destination must stay outside and must not contain the offline target;
- no blind whole-disk copy;
- passive approved data may enter `rescued-data`;
- executable/script/macro/archive/unknown or high-confidence IOC material remains in `containment`;
- deterministic IOC/YARA hashes already proven by the trusted RR-3 scan are carried into the effective RR-5 containment catalog;
- optional operator-approved RR-5 intel may be merged with trusted-scan high-confidence hashes;
- source remains read-only and byte-identical;
- source/destination SHA-256 verification remains mandatory;
- no repair execution, automatic restore, registry/boot write, source delete or recovery certification;
- B4-3 adds no new mutation authority to the source target.

B4-3 Windows acceptance must include Beta3 + B4-0..B4-3 regression, all predecessor deterministic gates, deterministic B4-3 acceptance, preview/no-copy gate, explicit execution gate, passive clean rescue, IOC containment, manifest SHA-256 verification, source unchanged, no service and B2 protected sources unchanged.

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
