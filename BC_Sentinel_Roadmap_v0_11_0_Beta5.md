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
- cumulative regression: **212 tests PASS**;
- READY / INCOMPLETE / UNSUPPORTED / LOCKED classifications PASS;
- live `SystemDrive` refused as offline target;
- target unchanged; no unlock/mount/write; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b50-pass
385ba83a483f6a894dd7048cc2d3cec9c11e3a8e
```

## B5-1 — Hostile / Damaged System Scenarios — accepted / frozen
Authoritative Windows acceptance:
- cumulative regression: **226 tests PASS**;
- `HEALTHY`, `DAMAGED`, `REVIEW_REQUIRED`, `ACCESS_RESTRICTED`, `IO_DEGRADED` PASS;
- symlink/reparse root refused before resolution;
- target unchanged; no repair/quarantine/write; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b51-pass
32bce8ccdeb65c266ef651a1dfb0849950d0f0e5
```

## B5-2 — Large-Scale & Stress Hardening — accepted / frozen
Authoritative Windows acceptance:
- cumulative regression: **239 tests PASS**;
- deterministic stress fixture: **12,005 files**;
- throughput about **1,855 files/s** against >= 100 files/s floor;
- Python traced peak about **19.7 MB** against <= 192 MiB ceiling;
- in-flight peak **64** against <= 64 bound;
- deep tree, large-file bounded sampling, partial file/time/cancel states PASS;
- live CLI fixture `COMPLETE`, **1503 files** probed;
- target byte-identical; no repair/quarantine/write; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b52-pass
d490f91aa16a5a2ae6f4660669f651619f1dd7b1
```

## B5-3 — Session Resume & Crash Recovery — accepted / frozen
Authoritative Windows acceptance:
- accepted B5-2 predecessor gate rerun: **239 tests PASS** plus all stress thresholds;
- **16 B5-3 tests PASS**, giving **255 cumulative tests covered**;
- hash-chained journal PASS;
- read-only resume PASS;
- repair/data-rescue interruption -> fresh confirmation required PASS;
- replay refused PASS;
- tampered evidence refused PASS;
- changed target fingerprint refused PASS;
- tampered journal/hash chain refused PASS;
- target unchanged; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b53-pass
3d7566b78a636327c103602d418ec1ece37979bc
```

## B5-4 — Advanced Recovery Decision Engine — current
Purpose: turn already-trusted Rescue evidence into a deterministic technician recommendation without replacing RR-6 certification semantics.

Allowed advisory states:
- `REPAIRABLE`;
- `MANUAL_REVIEW`;
- `DATA_RESCUE_ONLY`;
- `REIMAGE_RECOMMENDED`;
- `INDETERMINATE`.

Authority / precedence:
- B5-4 is advisory-only;
- RR-6/B4-4 outcome is authoritative and cannot be overridden;
- untrusted/tampered evidence -> `INDETERMINATE`;
- RR-6 `INDETERMINATE_REFUSED` -> `INDETERMINATE` even when a repair handoff exists;
- untrusted B5-3 resume/session -> `INDETERMINATE`;
- interrupted mutation-capable stage requiring confirmation -> `MANUAL_REVIEW` before any repairability recommendation;
- RR-6 `RECOVERED` is never translated into repair;
- later trusted evidence conflicting with `RECOVERED` fails closed;
- RR-6 `NOT_RECOVERED` + trusted B4-2 handoff may become `REPAIRABLE`;
- RR-6 `NOT_RECOVERED` + trusted executed B4-3 data rescue and no repair path may become `DATA_RESCUE_ONLY`;
- RR-6 `NOT_RECOVERED` without trusted recovery path may become `REIMAGE_RECOMMENDED`;
- reimage remains available when integrity cannot be demonstrated.

Evidence validation:
- mandatory B4-4 integrated certification summary;
- optional B5-1 assessment, B5-2 stress probe, B5-3 resume decision, B4-2 repair handoff, B4-3 data-rescue summary;
- internal stable SHA-256 verification for B4-4/B5-1/B5-2/B5-3;
- target fingerprint consistency;
- B4-2/B4-3 file hashes must match the B4-4 evidence index;
- evidence must be regular non-reparse files;
- any trust failure fails closed.

B5-4 acceptance must include:
- complete accepted B5-3 predecessor gate rerun first, preserving **255 cumulative predecessor tests covered**;
- **15 new B5-4 tests**, giving **270 cumulative tests covered**;
- deterministic acceptance matrix for all five advisory states;
- RR-6 refusal precedence PASS;
- repairable/data-rescue/reimage paths PASS;
- recovered technician-signoff behavior PASS;
- interrupted-mutation reconfirmation precedence PASS;
- tampered certification/assessment/binding fail-closed PASS;
- separate-process CLI live acceptance;
- advisory-only and RR-6-no-override flags verified;
- no service;
- B2 protected sources unchanged.

## B5-5 — Technician Report & Evidence Package
Purpose: produce a field-ready report and export package.

Required contents:
- discovered target and fingerprint;
- scan findings and confidence;
- repair plans/transactions/rollback state;
- rescued/contained files and hashes;
- certification outcome;
- B5-4 advisory decision and reasons;
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
