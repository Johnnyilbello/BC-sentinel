# BC Sentinel v0.11.0-beta.3 — RR-0 Architecture & Safety

Status: **implementation started — architecture/safety only**

Parent checkpoint: `checkpoint/v011-beta2-b2-pass-v6` at `b943f1ee550ad5c2bee3d8753962d5971c212381`.

## Goal
RR-0 defines the security boundary for BC Sentinel Rescue & Recovery before any portable repair, rescue USB, offline remediation, quarantine execution or recovery certification is implemented.

The design assumes the installed Windows environment may already be hostile, unreliable or partially controlled by malware. Therefore RR-0 is fail-closed and read-only by default.

## Non-goals
RR-0 does **not** implement:
- file deletion;
- process termination;
- host isolation;
- registry modification;
- boot/BCD modification;
- filesystem repair;
- quarantine execution;
- malware removal;
- recovery certification;
- automatic remediation;
- formatting/reimaging decisions.

Those capabilities, if ever introduced, belong to later milestones and must pass their own safety gates.

## Trust model

### Context A — Compromised Windows
The currently running Windows installation is treated as **untrusted**.

Allowed:
- evidence acquisition;
- filesystem inspection;
- registry inspection;
- evidence export.

Not allowed:
- quarantine planning that assumes trustworthy local state;
- repair planning that depends on trusted host interpretation;
- writes of any kind;
- recovery certification.

Any result obtained in this context is evidence, not proof that the machine is clean.

### Context B — Trusted external media
BC Sentinel runs from independently prepared trusted media while inspecting the target installation.

Allowed in RR-0:
- evidence acquisition;
- filesystem inspection;
- registry inspection;
- evidence export;
- generation of a future quarantine plan;
- generation of a future repair plan.

Still not allowed in RR-0:
- execution of quarantine or repair;
- boot/registry/filesystem writes;
- recovery certification.

### Context C — Offline image
A mounted disk/image is inspected without executing the target OS.

Allowed in RR-0:
- evidence acquisition;
- filesystem inspection;
- offline registry inspection;
- evidence export;
- generation of future quarantine/repair plans.

Still not allowed:
- modification of the image;
- declaring the source machine recovered.

## Safety invariants
The machine-readable contract in `sentinel/rescue_contract.py` enforces:
- `read_only_default = true`;
- no destructive action flag;
- no file delete;
- no process kill;
- no host isolation;
- no registry write;
- no boot write;
- no filesystem write;
- no recovery certification;
- SHA-256 for evidence hashing;
- explicit operator confirmation reserved for future mutation milestones;
- rollback plan required before any future mutation can be enabled;
- provenance required before any future mutation can be enabled;
- bounded workers and bounded in-flight work.

## Session model
Every future Rescue session must have an immutable session manifest with at minimum:
- `session_id`;
- `correlation_id`;
- execution context;
- target fingerprint;
- start timestamp;
- policy profile;
- evidence hash algorithm;
- explicit `write_authorized = false` in RR-0;
- explicit `recovery_certification_available = false` in RR-0.

A session manifest is an audit anchor, not a mutable runtime preference object.

## Audit/logging contract
Every meaningful stage must produce a structured record with:
- `session_id`;
- `correlation_id`;
- exact stage;
- component;
- status;
- exact reason;
- target when applicable;
- duration.

Required stage vocabulary:
1. `SESSION_START`
2. `TRUST_ASSESSMENT`
3. `TARGET_DISCOVERY`
4. `EVIDENCE_ACQUISITION`
5. `FILESYSTEM_INSPECTION`
6. `REGISTRY_INSPECTION`
7. `PLAN_GENERATION`
8. `INTEGRITY_ASSESSMENT`
9. `SESSION_CLOSE`

Failures must identify the exact stage and reason. Generic `failed` without stage/reason is not sufficient evidence.

## Path/device boundary
RR-0 architecture treats the following as security-sensitive and unresolved until later implementation supplies deterministic guards:
- symlinks;
- NTFS reparse points/junctions;
- mount points;
- device aliases;
- `GLOBALROOT`/device namespace paths;
- path traversal;
- alternate data streams;
- case/8.3 aliases;
- removable-device identity changes during a session.

No future repair engine may operate on a target path until canonical identity and containment have been proven.

## Offline registry/boot boundary
RR-0 allows inspection semantics only. Later milestones must separate:
- offline hive discovery;
- read-only hive parsing;
- startup/service/task persistence evidence;
- boot configuration evidence;
- write/remediation primitives.

Parsing success is never equivalent to permission to modify.

## Integrity and certification boundary
RR-0 cannot return `recovered`, `clean` or equivalent certification.

Future RR-6 certification must be able to return at least:
- `CERTIFIED` only with sufficient integrity evidence;
- `NOT_CERTIFIED` when evidence is incomplete;
- `REIMAGE_RECOMMENDED` when trustworthy recovery cannot be demonstrated.

Formatting/reimaging remains a valid last resort. The product must never claim recovery merely to avoid reimaging.

## Resource boundary
RR-0 defaults:
- max workers: 4;
- hard max workers: 8;
- max in-flight items: 128;
- hard max in-flight items: 256.

Later scanning milestones may refine these values only with measured performance evidence and bounded memory/CPU behavior.

## RR-0 acceptance gate
RR-0 passes only when all are true:
- architecture document present;
- `sentinel.rescue_contract` imports successfully;
- default policy validates;
- unsafe policy variants fail closed;
- compromised-Windows context cannot plan repair/quarantine;
- no context can certify recovery;
- immutable session manifest rejects write authorization;
- audit records require correlation, stage and reason;
- concurrency limits are bounded;
- automated tests pass;
- `tools.v011_beta3_rr0_acceptance` returns `passed=true`;
- no Production Service, realtime, EDR, quarantine or remediation source is modified merely to make RR-0 pass.

## Exit condition / next milestone
Only after RR-0 is accepted may work proceed to **RR-1 Portable**.

RR-1 must inherit every RR-0 invariant and remain non-destructive unless a later explicitly approved milestone introduces a separately gated mutation primitive.
