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
- root symlink/reparse refused before resolution;
- target unchanged; no repair/quarantine/write; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b51-pass
32bce8ccdeb65c266ef651a1dfb0849950d0f0e5
```

## B5-2 — Large-Scale & Stress Hardening — accepted / frozen
Authoritative Windows acceptance:
- cumulative regression: **239 tests PASS**;
- deterministic fixture: **12,005 files**;
- throughput comfortably above >= 100 files/s floor;
- Python traced peak well below <= 192 MiB ceiling;
- in-flight peak **64** against <= 64 bound;
- deep tree, bounded large-file sampling, explicit partial/cancel states PASS;
- target byte-identical; no repair/quarantine/write; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b52-pass
d490f91aa16a5a2ae6f4660669f651619f1dd7b1
```

## B5-3 — Session Resume & Crash Recovery — accepted / frozen
Authoritative Windows acceptance:
- accepted B5-2 predecessor gate rerun PASS;
- **16 B5-3 tests PASS**, giving **255 cumulative tests covered**;
- hash-chained journal and evidence binding PASS;
- read-only resume PASS;
- interrupted repair/data rescue requires fresh confirmation PASS;
- replay, changed target, tampered evidence and tampered journal refused PASS;
- target unchanged; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b53-pass
3d7566b78a636327c103602d418ec1ece37979bc
```

## B5-4 — Advanced Recovery Decision Engine — accepted / frozen
Authoritative Windows acceptance:
- complete B5-3 predecessor gate PASS;
- **15 B5-4 tests PASS**, giving **270 cumulative tests covered**;
- all advisory states verified: `REPAIRABLE`, `MANUAL_REVIEW`, `DATA_RESCUE_ONLY`, `REIMAGE_RECOMMENDED`, `INDETERMINATE`;
- RR-6 `INDETERMINATE_REFUSED` precedence PASS;
- RR-6 outcome can never be overridden;
- repair/data-rescue/reimage paths PASS;
- interrupted mutation reconfirmation precedence PASS;
- tampered evidence fails closed PASS;
- live `RECOVERED -> MANUAL_REVIEW` technician-signoff behavior PASS;
- advisory-only; no automatic repair/reimage; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b54-pass
f93e7d044b96bac9e72a31ee131d9c37ab18367b
```

## B5-5 — Technician Report & Evidence Package — current
Purpose: turn the accepted B5-4 advisory result and its evidence index into a field-ready, independently verifiable technician package without adding mutation authority.

Package layout:
- `technician-report.json` — machine-readable technician result;
- `technician-report.md` — human-readable result;
- `evidence-index.json` — trust/copy/provenance index;
- `package-manifest.json` — package-wide file/hash manifest;
- `evidence/` — SHA-256 verified copies of trusted source evidence.

Trust / provenance rules:
- B5-4 decision profile/schema/state/internal `decision_sha256` revalidated before export;
- decision must bind to the exact current offline-target fingerprint;
- every evidence item marked trusted by B5-4 must still exist outside target and match its bound SHA-256;
- trusted evidence drift/missing/reparse -> build refusal;
- evidence marked untrusted by B5-4 is never promoted or copied as trusted;
- untrusted evidence remains visible as unresolved risk in report/index;
- decision, evidence and existing package paths are checked for symlink/reparse before path resolution;
- post-export verification refuses manifest-listed symlink/reparse substitution and unlisted files.

Hard bounds:
- max 64 evidence entries;
- max 256 MiB per copied evidence file;
- max 1 GiB copied package evidence budget;
- output only outside target;
- no network/cloud dependency.

Report requirements:
- target fingerprint;
- RR-6 outcome/certification flag preserved exactly;
- B5-4 advisory state/reasons and next action;
- unresolved risks/refusals;
- data-rescue summary when available;
- evidence counts and provenance;
- report-only safety contract;
- stable report/index/manifest SHA-256 values.

B5-5 acceptance must include:
- complete accepted B5-4 predecessor gate first, preserving **270 cumulative predecessor tests covered**;
- **15 new B5-5 tests**, giving **285 cumulative tests covered**;
- deterministic trusted/untrusted evidence package PASS;
- human + JSON report PASS;
- evidence hash index PASS;
- package manifest and independent verify PASS;
- exported-evidence tamper detection PASS;
- listed-file reparse substitution detection PASS;
- trusted source drift refusal PASS;
- untrusted risk preservation PASS;
- separate-process CLI `build` and `verify` PASS;
- target byte-identical;
- no repair/quarantine/data-rescue/reimage execution;
- no service;
- B2 protected sources unchanged.

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
