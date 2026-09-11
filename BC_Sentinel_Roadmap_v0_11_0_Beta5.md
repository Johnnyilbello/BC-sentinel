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

## B5-0 — Real-World Target Discovery — accepted
Authoritative Windows acceptance:
- Beta3 + complete Beta4 + B5-0 regression: **212 tests PASS**;
- deterministic multi-volume fixture PASS;
- READY / INCOMPLETE / UNSUPPORTED / LOCKED classifications PASS;
- live Windows volume enumeration bounded;
- live `SystemDrive` explicitly refused as offline target;
- target unchanged;
- no unlock/mount/write;
- no service registration;
- B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b50-pass
385ba83a483f6a894dd7048cc2d3cec9c11e3a8e
```

## B5-1 — Hostile / Damaged System Scenarios — current
Purpose: harden the Rescue workflow against realistic damage and hostile filesystem conditions while remaining read-only.

Required coverage:
- missing/corrupt critical files;
- broken ACLs and unreadable paths;
- partial directory trees;
- simulated persistent malware/startup artifacts;
- slow I/O;
- intermittent read failures;
- reparse/symlink traps;
- bounded file/byte/time budgets;
- output outside target;
- explicit reason/state for every refusal or degraded condition.

Allowed assessment states:
- `HEALTHY`;
- `REVIEW_REQUIRED`;
- `DAMAGED`;
- `ACCESS_RESTRICTED`;
- `IO_DEGRADED`;
- `REFUSED`.

Rules:
- no state automatically triggers repair, quarantine, delete, restore or certification;
- target code is never executed/loaded;
- uncertainty never becomes success;
- critical target-contract failure is `DAMAGED`;
- suspicious persistence is operator review only;
- permission/I/O failures are preserved as explicit degraded states;
- no network/cloud requirement.

B5-1 Windows acceptance must include:
- complete Beta3 + Beta4 + B5-0 regression;
- 14 new B5-1 tests, expected cumulative **226 tests**;
- clean fixture -> `HEALTHY`;
- missing critical file -> `DAMAGED`;
- persistence fixture -> `REVIEW_REQUIRED`;
- deterministic permission case -> `ACCESS_RESTRICTED`;
- deterministic I/O failure -> `IO_DEGRADED`;
- target byte-identical;
- no repair/quarantine/write;
- no service;
- B2 protected sources unchanged.

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
