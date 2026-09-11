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

## B5-2 — Large-Scale & Stress Hardening — accepted / frozen
Authoritative Windows acceptance:
- cumulative regression: **239 tests PASS**;
- deterministic stress fixture probed **12,005 files**;
- throughput **1855.418 files/s** against >= 100 files/s floor;
- Python traced peak **19,694,597 bytes** against <= 192 MiB ceiling;
- in-flight peak **64** against <= 64 bound;
- 40-level deep-tree coverage PASS;
- 8 MiB file bounded sampling PASS;
- explicit file-limit / time-limit / cancellation partial states PASS;
- live CLI fixture `COMPLETE`, **1503 files** probed;
- target byte-identical;
- no repair/quarantine/write;
- no service registration;
- B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b52-pass
d490f91aa16a5a2ae6f4660669f651619f1dd7b1
```

## B5-3 — Session Resume & Crash Recovery — current
Purpose: allow interrupted Rescue sessions to continue without duplicating actions or losing evidence trust, while never converting an interrupted mutation-capable stage into automatic consent.

Implementation contract:
- profile `v0.11.0-beta.5-b53`;
- durable JSON journal outside target using atomic replace;
- journal binds session ID, correlation ID, target root and target fingerprint;
- every event is sequence-bound and SHA-256 hash-chain bound;
- every event has an idempotent operation key;
- linked evidence files are SHA-256 bound and must remain outside target;
- resume revalidates journal schema/profile, complete event chain, operation-key uniqueness, journal hash, target fingerprint and evidence hashes;
- any mismatch fails closed as `REFUSED`;
- read-only stages may return `RESUME_READ_ONLY_ALLOWED` after `PLANNED`, `STARTED` or `INTERRUPTED`;
- repair handoff/execute/rollback and data rescue return `RECONFIRM_REQUIRED` after interruption;
- terminal states `COMPLETED`, `REFUSED`, `ROLLED_BACK` return `SKIP_TERMINAL`;
- exact event replay is refused;
- B5-3 does not preserve an old RR-4B confirmation as reusable consent;
- no automatic repair, rollback, quarantine or data-rescue continuation;
- no target-write, registry/boot-write, service/driver or network/cloud authority added.

B5-3 acceptance must include:
- accepted B5-2 complete gate rerun first, preserving the **239-test** predecessor regression and stress thresholds;
- **16 new B5-3 tests**, giving **255 cumulative tests covered**;
- live session initialized in one process and resumed from later processes;
- interrupted read-only stage -> `RESUME_READ_ONLY_ALLOWED`;
- interrupted repair -> `RECONFIRM_REQUIRED`;
- interrupted data rescue -> `RECONFIRM_REQUIRED`;
- duplicate operation replay refused;
- tampered evidence refused;
- changed target fingerprint refused;
- tampered journal/hash chain refused;
- journal/evidence outside target;
- target byte-identical in live gate;
- no service;
- B2 protected sources unchanged.

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
