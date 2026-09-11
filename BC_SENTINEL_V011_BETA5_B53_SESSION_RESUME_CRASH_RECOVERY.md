# BC Sentinel v0.11.0-beta.5 — B5-3 Session Resume & Crash Recovery

## Purpose
B5-3 makes Rescue sessions durable across Console closure, process crash and technician restart without granting any new mutation authority.

Profile: `v0.11.0-beta.5-b53`

## Core rule
Resume is allowed only after the session trust chain is revalidated. A previous session file is evidence, not authority.

B5-3 validates:
- journal schema/profile;
- event sequence;
- SHA-256 hash chain;
- unique operation keys for replay prevention;
- journal SHA-256;
- target root binding;
- current target fingerprint;
- hashes of linked evidence files;
- evidence location outside target.

Any mismatch fails closed.

## Durable journal
The journal is written outside the target with atomic replacement. It records:
- session ID;
- correlation ID;
- target root;
- target fingerprint;
- ordered events;
- event state;
- evidence path/hash when supplied;
- previous event hash;
- operation key;
- journal hash;
- safety contract.

Event states:
- `PLANNED`;
- `STARTED`;
- `COMPLETED`;
- `REFUSED`;
- `ROLLED_BACK`;
- `INTERRUPTED`.

## Resume classes
Read-only stages may be proposed for resume after `PLANNED`, `STARTED` or `INTERRUPTED`:
- target validation;
- evidence inventory;
- offline scan;
- health assessment;
- stress probe;
- integrity certification.

Their resume decision is `RESUME_READ_ONLY_ALLOWED` only when the complete session remains trusted.

Operator-gated / mutation-capable stages never auto-resume:
- repair handoff;
- repair execute;
- repair rollback;
- data rescue.

After interruption they return `RECONFIRM_REQUIRED`. Existing RR-4B / B4-2 confirmation semantics remain authoritative for repair execution and rollback. B5-3 does not manufacture or preserve an old confirmation as reusable consent.

Terminal stages (`COMPLETED`, `REFUSED`, `ROLLED_BACK`) are returned as `SKIP_TERMINAL` by resume planning.

## Replay prevention
Each event receives an operation key derived from session, stage, state, reason and evidence binding. Re-submitting the exact same event is refused as an idempotent replay.

## Tamper behavior
Resume becomes `REFUSED` when any of the following is detected:
- modified event content;
- broken previous-event hash;
- duplicate operation key in the journal;
- journal SHA mismatch;
- changed target fingerprint;
- changed/missing evidence;
- invalid target contract;
- evidence moved inside the target.

No refused session is automatically repaired or reconstructed by guessing.

## Safety boundary
B5-3 adds no:
- target write authority;
- automatic repair;
- automatic rollback;
- automatic data-rescue continuation;
- quarantine execution;
- registry/boot write;
- service or driver installation;
- network/cloud requirement.

## Acceptance
`TEST-V011-BETA5-B53.ps1` first reruns the accepted B5-2 complete gate, preserving the full 239-test predecessor regression and stress thresholds.

B5-3 then adds 16 tests covering:
- journal creation outside target;
- workspace-inside-target refusal;
- read-only started/interrupted resume;
- repair reconfirmation;
- data-rescue reconfirmation;
- terminal stage skip;
- duplicate replay refusal;
- event hash-chain linkage;
- journal tamper refusal;
- target fingerprint change refusal;
- evidence verification;
- evidence tamper refusal;
- inside-target evidence refusal;
- root symlink/reparse refusal before resolution;
- decision hash and no-mutation authority.

Cumulative coverage: **255 tests** (239 accepted predecessor tests + 16 B5-3 tests), plus deterministic B5-3 acceptance and live multi-process session resume.

## Live Windows acceptance
The live gate must prove:
- session initialization in one process;
- interrupted read-only scan recorded in later processes;
- interrupted repair and data-rescue states recorded;
- fresh process resume returns read-only resume allowed;
- repair/data rescue return `RECONFIRM_REQUIRED`;
- exact event replay is refused;
- tampered evidence changes resume to `REFUSED`;
- target remains byte-identical;
- no Windows service is registered;
- protected B2 service/realtime/EDR sources remain unchanged.

## Freeze rule
B5-3 is not accepted or frozen until the authoritative non-elevated Windows gate is completely green. No predecessor threshold or trust rule may be weakened to obtain PASS.
