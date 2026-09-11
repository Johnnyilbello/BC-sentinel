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
- target unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b40-pass
3bb5d0553397cccefba31eac70c09a99305e2492
```

## B4-1 — Evidence Inventory + Guided Scan — accepted
Authoritative Windows acceptance:
- Beta3 + B4-0 + B4-1 regression: **157 tests PASS**;
- fresh RR-3 scan, trusted reuse and tampered-evidence refusal PASS;
- no automatic repair/quarantine;
- target unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b41-pass
5049b2246df692c0f417131af44353cc234e1f95
```

## B4-2 — Guided Repair Handoff — accepted
Authoritative Windows acceptance:
- Beta3 + B4-0..B4-2 regression: **167 tests PASS**;
- trusted scan binding, approved operations binding and plan-bound confirmation PASS;
- RR-4B execute/rollback regression PASS;
- Console performs no automatic repair;
- target unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b42-pass
cb6ef6dd65ed9528c4613f896e0c84fde66ffc79
```

## B4-3 — Guided Safe Data Rescue — accepted
Accepted boundary:
- trusted RR-3 evidence required;
- explicit selections only under accepted RR-5 `Users/<profile>` scope;
- preview creates plan only and copies no data;
- copying requires explicit operator execution request;
- destination remains outside the target;
- passive data may enter `rescued-data`;
- executable/script/macro/archive/unknown/high-confidence IOC material remains in `containment`;
- trusted RR-3 IOC/YARA hashes are carried into RR-5 containment intel;
- source remains read-only and byte-identical;
- SHA-256 verification remains mandatory;
- no repair execution, automatic restore or recovery certification.

Authoritative Windows acceptance:
- Beta3 + B4-0..B4-3 regression: **176 tests PASS**;
- preview/no-copy PASS;
- explicit selection PASS;
- passive clean rescue PASS;
- deterministic IOC containment PASS;
- RR-5 manifest SHA-256 verification PASS;
- source unchanged, no service, B2 protected sources unchanged;
- final B4-3 core and bootstrap PASS.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b43-pass
641472a24d3f41feaf4351d65405c39b09622d67
```

## B4-4 — Integrated Certification + Session Summary — current
Purpose: validate continuity of the Beta4 session, invoke frozen RR-6 only when the session evidence is trusted, and emit one final auditable session outcome.

Required boundaries:
- B4-0 session plan must match the current target fingerprint;
- RR-3 scan must still be `TRUSTED` under B4-1 validation;
- optional B4-2 handoff must match the same target fingerprint and exact trusted scan SHA-256;
- any supplied repair transaction requires B4-2 handoff and must match the exact RR-4B plan SHA-256;
- optional B4-3 summary must match the same target fingerprint and scan SHA-256;
- executed B4-3 rescue requires a valid RR-5 manifest hash, matching source root and zero manifest errors;
- baseline, provenance, transaction and outputs remain outside target;
- session-continuity failure returns `INDETERMINATE_REFUSED` before RR-6;
- when session continuity is trusted, RR-6 is invoked unchanged;
- RR-6 outcomes are preserved exactly: `RECOVERED`, `NOT_RECOVERED`, `INDETERMINATE_REFUSED`;
- B4-4 writes a session summary binding all relevant evidence hashes and RR-6 report hash;
- target remains byte-identical;
- no repair execution or new mutation authority is added;
- reimage/format is never suppressed when trust cannot be demonstrated.

B4-4 Windows acceptance must include:
- Beta3 + B4-0..B4-4 regression, expected **188 tests**;
- all predecessor deterministic gates;
- clean integrated session -> `RECOVERED`;
- trusted unresolved IOC -> `NOT_RECOVERED`;
- session binding failure -> `INDETERMINATE_REFUSED` before RR-6;
- RR-6 trust/provenance failure -> `INDETERMINATE_REFUSED` from RR-6;
- summary hash and RR-6 report binding verification;
- target unchanged, no service and B2 protected sources unchanged.

## B4-5 — Portable Rescue Console
Package the accepted integrated workflow as a standard-user portable application/CLI without installer/service/driver requirements.

Acceptance must prove:
- built artifact integrity;
- no service registration;
- no new live-host mutation authority;
- Beta3 + complete Beta4 regression green;
- built application preserves all operator gates and all three final outcome classes;
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
