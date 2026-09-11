# BC Sentinel — Roadmap v0.11.0-beta.5 Real-World Rescue Hardening

## Frozen predecessor
Beta5 starts only from the accepted Beta4 Portable Rescue Console checkpoint:

```text
checkpoint/v011-beta4-b45-pass
823ec10ff20157661e66418ac977c0827a654e29
```

Beta3 Rescue & Recovery and Beta4 Rescue Console checkpoints are immutable predecessors. Beta5 must not weaken accepted operator gates, trust precedence, rollback guarantees, refusal semantics or protected B2 service/realtime/EDR sources.

## Beta5 goal
Move BC Sentinel Rescue from technically accepted synthetic/offline workflows toward dependable field use on real damaged, slow, partially inaccessible or compromised Windows systems.

Beta5 is hardening, observability and field validation. It is not permission to add automatic destructive behavior.

## B5-0 — Real-World Target Discovery — current
Purpose: discover candidate offline Windows installations safely across realistic storage layouts without modifying disks.

Required boundaries:
- enumerate candidate roots from explicit paths and discovered volumes in read-only mode;
- support multiple disks/partitions and more than one Windows candidate;
- validate each candidate using required Windows markers without executing or loading target code;
- classify candidate state as `READY`, `LOCKED`, `ACCESS_DENIED`, `INCOMPLETE`, `UNSUPPORTED` or `ERROR`;
- detect likely BitLocker/locked-volume conditions and refuse safely when not readable;
- never attempt unlock, mount mutation, format, partition changes, BCD changes or filesystem repair;
- normalize and log volume/root paths, discovery source, stage, reason, elapsed time and correlation ID;
- cap enumeration and timeout/volume counts;
- preserve all Beta4 target-validation rules before any later Rescue stage can run;
- no installer/service/driver and no network/cloud requirement.

Acceptance must include synthetic multi-volume fixtures, inaccessible/partial candidates, locked-volume classification, bounded enumeration, deterministic ordering, target byte-identical checks, no service, B2 protected sources unchanged and complete Beta3+Beta4 regression.

## B5-1 — Hostile / Damaged System Scenarios
Purpose: harden the Rescue workflow against realistic damage and hostile filesystem conditions.

Scenarios:
- missing/corrupt critical files;
- broken ACLs and unreadable paths;
- partial directory trees;
- malformed metadata;
- stale or inconsistent evidence;
- simulated persistent malware artifacts;
- extremely slow filesystems;
- reparse/symlink/junction traps;
- intermittent read failures.

Required outcome: fail closed, preserve evidence, expose exact stage/reason, never convert uncertainty into success.

## B5-2 — Large-Scale & Stress Hardening
Purpose: prove bounded behavior under real technician workloads.

Required coverage:
- tens/hundreds of thousands of files;
- deep directory trees;
- large individual files;
- CPU/RAM/I/O pressure;
- bounded workers/queues;
- cancellation and timeout safety;
- deterministic partial-result semantics;
- no unbounded memory growth;
- explicit performance metrics and regression thresholds.

## B5-3 — Session Resume & Crash Recovery
Purpose: allow interrupted Rescue sessions to continue without duplicating actions or losing evidence trust.

Required boundaries:
- durable session journal outside target;
- resume only when target fingerprint and evidence hashes still match;
- idempotent replay prevention;
- distinguish planned, started, completed, refused and rolled-back stages;
- crash/restart simulation;
- interrupted repair/data rescue never auto-resumes mutation;
- operator confirmation must be re-established where required.

## B5-4 — Advanced Recovery Decision Engine
Purpose: summarize trusted evidence into an operator decision without replacing RR-6 certification semantics.

Allowed advisory states:
- `REPAIRABLE`;
- `MANUAL_REVIEW`;
- `DATA_RESCUE_ONLY`;
- `REIMAGE_RECOMMENDED`;
- `INDETERMINATE`.

Rules:
- advisory state cannot override RR-6 outcome;
- `INDETERMINATE_REFUSED` can never be translated to recovered/repairable certainty;
- reimage remains available when integrity cannot be demonstrated;
- decisions must list evidence and reasons.

## B5-5 — Technician Report & Evidence Package
Purpose: produce a field-ready report and export package.

Required contents:
- discovered target and fingerprint;
- scan findings and confidence;
- repair plans/transactions/rollback state;
- rescued/contained files and hashes;
- certification outcome;
- unresolved risks and refusal reasons;
- recommended next action;
- complete evidence hash index and provenance;
- human-readable summary plus machine-readable JSON.

## B5-6 — Controlled Real-PC Acceptance
Purpose: validate Beta5 on real hardware under controlled conditions.

Required scenarios:
- known-good control PC/disk;
- intentionally damaged test Windows installation;
- simulated malware/persistence fixture;
- slow or resource-constrained system;
- locked/encrypted candidate refusal;
- interrupted session/resume;
- real problematic PC when safely available.

No milestone passes on anecdotal success. Every run requires before/after integrity evidence and acceptance logs.

## B5-7 — Portable Technician Release
Purpose: package the accepted Beta5 field-hardened workflow as the technician release.

Acceptance must prove:
- built artifact integrity;
- standard-user portable execution where applicable;
- no installer/service/driver requirement;
- no new automatic destructive authority;
- complete Beta3+Beta4+Beta5 regression;
- built-artifact field workflow acceptance;
- protected B2 service/realtime/EDR sources unchanged;
- final checkpoint freeze.

## Beta5 closure condition
Beta5 closes only after B5-0 through B5-7 pass deterministic tests, Windows built-artifact gates and controlled real-hardware acceptance. No threshold may be weakened merely to obtain PASS.

## Logging / observability policy
Critical failures must expose enough information to identify root cause immediately:
- exact stage/component;
- normalized root/volume/path;
- session/correlation ID;
- reason/cause and exception class;
- component state;
- child-process PID/exit code when relevant;
- counters before/after;
- timings;
- target/evidence hashes when useful;
- retry/refusal classification.

Diagnostic/acceptance logging may be verbose. Production logging must remain structured, bounded and rate-limited.

## Codex reasoning policy
- **Extra High**: trust boundaries, disk/volume discovery safety, repair/resume semantics, certification/decision logic, real-PC acceptance design.
- **High**: implementation, tests, packaging and observability after the safety contract is fixed.
- milestone-by-milestone only; preserve budget by avoiding broad speculative rewrites.
