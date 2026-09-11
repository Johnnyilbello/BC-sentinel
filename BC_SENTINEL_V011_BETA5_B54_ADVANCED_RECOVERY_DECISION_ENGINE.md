# BC Sentinel v0.11.0-beta.5 — B5-4 Advanced Recovery Decision Engine

## Purpose
B5-4 converts already-trusted Rescue evidence into an explicit technician recommendation without changing RR-6 certification semantics and without adding mutation authority.

Profile: `v0.11.0-beta.5-b54`

## Advisory states
The engine may emit only:
- `REPAIRABLE`
- `MANUAL_REVIEW`
- `DATA_RESCUE_ONLY`
- `REIMAGE_RECOMMENDED`
- `INDETERMINATE`

These are advisory states, not certification outcomes.

## Authority and precedence
RR-6/B4-4 remains authoritative.

Hard precedence rules:
1. untrusted/tampered evidence -> `INDETERMINATE`;
2. RR-6 `INDETERMINATE_REFUSED` -> `INDETERMINATE` regardless of repair/data-rescue evidence;
3. untrusted B5-3 resume/session -> `INDETERMINATE`;
4. interrupted mutation-capable stage requiring fresh confirmation -> `MANUAL_REVIEW` before any repairability recommendation;
5. RR-6 `RECOVERED` is never translated into a repair recommendation;
6. later trusted evidence conflicting with `RECOVERED` fails closed;
7. RR-6 `NOT_RECOVERED` with a trusted B4-2 repair handoff may become `REPAIRABLE`;
8. RR-6 `NOT_RECOVERED` with trusted executed B4-3 data rescue and no repair path may become `DATA_RESCUE_ONLY`;
9. RR-6 `NOT_RECOVERED` without a trusted recovery path may become `REIMAGE_RECOMMENDED`.

## Evidence validation
B5-4 can consume:
- mandatory B4-4 integrated certification summary;
- optional B5-1 hostile/damaged assessment;
- optional B5-2 stress probe;
- optional B5-3 resume decision;
- optional B4-2 guided repair handoff;
- optional B4-3 guided data-rescue summary.

Validation includes:
- expected profile/schema;
- internal stable SHA-256 verification for B4-4/B5-1/B5-2/B5-3;
- target fingerprint consistency;
- B4-2/B4-3 file-hash binding to the B4-4 evidence index;
- operator-confirmation contract for B4-2;
- non-reparse regular evidence files.

Any failed trust check produces `INDETERMINATE` rather than falling back to an optimistic state.

## RECOVERED handling
RR-6 `RECOVERED` remains recovered. B5-4 emits `MANUAL_REVIEW` only as a technician sign-off/advisory state because the B5-4 vocabulary intentionally has no second certification state.

If later B5-1 evidence reports `DAMAGED`, `ACCESS_RESTRICTED`, `IO_DEGRADED` or `REFUSED`, B5-4 emits `INDETERMINATE` because the later evidence conflicts with the prior recovery certification.

If a B5-2 probe is partial, the recommendation remains `MANUAL_REVIEW` until the bounded probe is completed or explicitly accepted by the technician.

## NOT_RECOVERED handling
- trusted B4-2 repair handoff -> `REPAIRABLE`, still requiring the existing RR-4B plan-bound explicit confirmation;
- trusted B4-3 executed data rescue without repair path -> `DATA_RESCUE_ONLY`;
- no trusted repair/rescue path -> `REIMAGE_RECOMMENDED`;
- interrupted repair/data-rescue requiring B5-3 reconfirmation -> `MANUAL_REVIEW` first.

## Safety contract
B5-4:
- is advisory-only;
- cannot override RR-6;
- cannot execute repair;
- cannot execute data rescue;
- cannot execute reimage/format;
- cannot quarantine/delete;
- adds no target-write authority;
- adds no repair-execution authority;
- adds no quarantine-execution authority;
- requires no network/cloud service.

## Decision output
The JSON output contains:
- RR-6 outcome and certification flag;
- advisory state;
- ordered reasons;
- explicit next action;
- evidence file/hash index;
- health/stress/resume/repair/data-rescue signals;
- safety contract;
- stable `decision_sha256` excluding volatile timestamp/timing fields.

## B5-4 tests
15 dedicated tests cover:
- RR-6 refusal precedence;
- repairable path;
- data-rescue-only path;
- reimage recommendation;
- recovered technician sign-off;
- reconfirmation precedence;
- recovered-vs-damage conflict;
- incomplete stress probe;
- B4-4 tampering;
- B5-1 tampering;
- B5-2 fingerprint mismatch;
- untrusted B5-3 session;
- B4-2 file-binding mismatch;
- advisory safety and decision hash.

Cumulative coverage target after accepted B5-3: **270 tests** (255 predecessor coverage + 15 B5-4 tests).

## Windows gate
`TEST-V011-BETA5-B54.ps1`:
1. runs the accepted complete B5-3 predecessor gate;
2. compile-checks B5-4;
3. runs all 15 B5-4 tests;
4. runs the deterministic five-state acceptance matrix;
5. creates a persistent live evidence fixture;
6. runs the B5-4 CLI in a separate process;
7. verifies RR-6 outcome preservation and advisory-only flags;
8. verifies no Windows service and protected B2 sources unchanged.

## Acceptance rule
B5-4 is frozen only after the authoritative non-elevated Windows gate is fully green. No state, trust check or predecessor threshold may be weakened merely to obtain PASS.
