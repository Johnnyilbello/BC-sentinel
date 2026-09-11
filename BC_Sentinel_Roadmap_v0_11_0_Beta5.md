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

## B5-0 — Real-World Target Discovery — accepted / frozen
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

## B5-1 — Hostile / Damaged System Scenarios — accepted / frozen
Authoritative Windows acceptance:
- Beta3 + complete Beta4 + B5-0..B5-1 regression: **226 tests PASS**;
- clean target -> `HEALTHY`;
- missing critical file -> `DAMAGED`;
- persistence fixture -> `REVIEW_REQUIRED`;
- deterministic permission case -> `ACCESS_RESTRICTED`;
- deterministic I/O failure -> `IO_DEGRADED`;
- symlink/reparse root refused before resolution;
- target unchanged;
- no repair/quarantine/write;
- no service registration;
- B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b51-pass
32bce8ccdeb65c266ef651a1dfb0849950d0f0e5
```

## B5-2 — Large-Scale & Stress Hardening — current
Purpose: prove bounded behavior under real technician workloads without adding mutation authority.

Required coverage:
- tens/hundreds of thousands of files;
- deep directory trees;
- large individual files;
- CPU/RAM/I/O pressure;
- bounded workers and in-flight work;
- cancellation and timeout safety;
- deterministic partial-result semantics;
- no unbounded memory growth;
- explicit performance metrics and regression thresholds.

B5-2 implementation contract:
- profile `v0.11.0-beta.5-b52`;
- read-only offline target probe validated through the existing RR-6 target contract;
- hard ceilings: 200,000 files, 8 GiB sampled-byte budget, 120 s elapsed budget, depth 256, workers 8, in-flight 512, sample 1 MiB;
- normal defaults remain lower than hard ceilings;
- bounded `ThreadPoolExecutor` with explicit `max_workers` and `max_inflight`;
- samples files rather than loading large files fully;
- iterative directory walk, no recursive Python call stack;
- symlink/reparse paths skipped and root symlink/reparse refused before resolution;
- partial states are not success: `PARTIAL_FILE_LIMIT`, `PARTIAL_BYTE_LIMIT`, `PARTIAL_TIME_LIMIT`, `PARTIAL_DEPTH_LIMIT`, `CANCELLED`;
- complete probe with read/enumeration errors becomes `DEGRADED`;
- stable SHA-256 probe hash excludes volatile timing metrics;
- performance report includes elapsed ms, files/s, sampled MiB/s, Python peak memory and in-flight peak;
- output only outside target using atomic replace;
- no repair, quarantine, delete, registry/boot write, target execution, network or cloud requirement.

B5-2 Windows acceptance must include:
- complete Beta3 + Beta4 + B5-0..B5-1 regression;
- **13 new B5-2 tests, expected cumulative 239 tests**;
- deterministic fixture with 12,000 bulk files plus Windows markers, deep tree and large file;
- full stress state `COMPLETE`;
- file-limit state `PARTIAL_FILE_LIMIT`;
- cancellation state `CANCELLED`;
- time-limit state `PARTIAL_TIME_LIMIT`;
- depth-limit state `PARTIAL_DEPTH_LIMIT` when pruning occurs;
- deep-tree coverage at 40 levels without reliance on Windows Long Paths policy;
- large 8 MiB file sampled with bounded 64-byte sample;
- throughput floor >= 100 files/s on deterministic local fixture;
- Python peak-memory ceiling <= 192 MiB;
- worker bound <= 4 and in-flight peak <= 64 for deterministic acceptance;
- live CLI fixture with 1,500 additional files;
- target byte-identical;
- no service;
- B2 protected sources unchanged.

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
