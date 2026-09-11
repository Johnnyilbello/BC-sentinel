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

## B5-5 — Technician Report & Evidence Package — accepted / frozen
Authoritative Windows acceptance:
- complete B5-4 predecessor gate PASS;
- **15 B5-5 tests PASS**, giving **285 cumulative tests covered**;
- human + JSON technician report PASS;
- evidence hash index and package manifest PASS;
- independent package verify PASS;
- exported-evidence tamper detection PASS;
- listed-file reparse substitution detection PASS;
- trusted source drift refusal PASS;
- untrusted evidence remains explicit risk and is not copied as trusted PASS;
- live `RECOVERED -> MANUAL_REVIEW` report preservation PASS;
- target unchanged; no repair/quarantine/data-rescue/reimage execution; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta5-b55-pass
26bc2a365403658bb33881fb605101245cf87b5c
```

## B5-6 — Controlled Real-PC Acceptance — current
Purpose: validate the accepted Beta5 workflow on an actual Windows host while keeping simulated damage clearly separated from real-hardware evidence.

Environment labels:
- `REAL_HARDWARE`;
- `CONTROLLED_OFFLINE_FIXTURE`;
- `OPERATOR_SUPPLIED`.

Required normal-gate scenarios:
1. `known_good_control` — must be `REAL_HARDWARE`;
2. `damaged_offline_windows` — controlled offline fixture;
3. `persistence_fixture` — controlled offline fixture;
4. `resource_constrained` — controlled bounded/stress fixture;
5. `locked_encrypted_refusal` — controlled refusal proof, no unlock/mount mutation;
6. `interrupted_session_resume` — controlled B5-3-backed resume proof.

Optional field scenario:
- `problematic_pc_optional` — remains `NOT_RUN` until a genuinely problematic PC can be tested safely;
- it must never be replaced by a fixture merely to obtain PASS;
- a later field run may explicitly require it.

Evidence / trust rules:
- every scenario has profile/schema/environment/status;
- every scenario has a host fingerprint and before/after target/control fingerprint;
- every evidence file has exact size + SHA-256 binding;
- scenario records have stable `scenario_sha256`;
- symlink/reparse scenario/evidence paths are refused;
- duplicate/missing/tampered scenario records fail closed;
- `known_good_control` cannot pass unless labeled `REAL_HARDWARE`;
- fixture labels remain explicit in the final summary;
- refusal scenarios require explicit refusal reasons;
- safety contract forbids new repair/quarantine/format/reimage/registry/boot authority.

Predecessor evidence reused by B5-6:
- B5-0 locked/refusal acceptance;
- B5-1 damage + persistence acceptance;
- B5-2 stress/bounded-resource acceptance;
- B5-3 interruption/resume acceptance;
- B5-4 decision acceptance;
- B5-5 technician package acceptance.

B5-6 acceptance must include:
- complete accepted B5-5 predecessor gate first, preserving **285 cumulative predecessor tests covered**;
- **16 new B5-6 tests**, giving **301 cumulative tests covered**;
- real Windows host control record PASS;
- at least five explicitly labeled controlled fixture records PASS/accepted refusal;
- same-host coverage binding PASS;
- locked/encrypted candidate refusal with no unlock/mount mutation PASS;
- fixture-not-real-hardware labeling PASS;
- problematic PC remains `NOT_RUN` in the standard gate;
- persistent acceptance evidence directory generated;
- no automatic destructive authority;
- no service;
- B2 protected sources unchanged.

Passing B5-6 does not claim that every real infected PC is recoverable without reimage. It proves the controlled real-host validation framework and preserves a separate slot for a genuine problematic-PC field case.

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

A genuine problematic-PC field case remains separately traceable and must never be fabricated. If it is not safely available during the standard B5-6 gate, it remains `NOT_RUN` and can be required in a later field validation.

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
