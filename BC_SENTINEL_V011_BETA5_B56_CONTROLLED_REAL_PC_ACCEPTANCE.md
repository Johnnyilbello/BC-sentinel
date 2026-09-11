# BC Sentinel v0.11.0-beta.5 — B5-6 Controlled Real-PC Acceptance

## Purpose
B5-6 moves Beta5 from synthetic-only validation toward field evidence while preserving the accepted Rescue safety model.

Profile: `v0.11.0-beta.5-b56`

B5-6 does not add repair, quarantine, unlock, format, reimage, registry-write, boot-write, service or driver authority. It validates evidence produced on a real Windows host and on explicitly labeled controlled offline fixtures.

## Scenario vocabulary
Every scenario must be labeled as exactly one of:
- `REAL_HARDWARE`
- `CONTROLLED_OFFLINE_FIXTURE`
- `OPERATOR_SUPPLIED`

A fixture must never be labeled `REAL_HARDWARE`.

Scenario statuses:
- `PASS`
- `FAIL`
- `REFUSED`
- `NOT_RUN`

## Required scenarios
The normal B5-6 gate requires six records:
1. `known_good_control`
2. `damaged_offline_windows`
3. `persistence_fixture`
4. `resource_constrained`
5. `locked_encrypted_refusal`
6. `interrupted_session_resume`

`problematic_pc_optional` remains optional until a real problematic machine can be tested safely. It must stay `NOT_RUN` rather than being represented by a fixture.

A later field run may pass `--require-problematic-pc`; in that mode the optional scenario becomes mandatory and must have real/operator-supplied evidence.

## Real-host control
The `known_good_control` record must be `REAL_HARDWARE`.

The Windows gate records:
- live host/platform information;
- a stable host fingerprint;
- protected B2 source hashes;
- the accepted B5-5 predecessor result;
- a control snapshot fingerprint before/after the B5-6 process.

The control does not claim that the complete live Windows installation was scanned as an offline target. It proves that the actual host executed the acceptance workflow and that protected Sentinel sources remained unchanged.

## Controlled fixture scenarios
The remaining mandatory scenarios are explicitly `CONTROLLED_OFFLINE_FIXTURE` and are backed by accepted predecessor evidence:
- locked/encrypted refusal -> B5-0 acceptance;
- damaged critical-file scenario -> B5-1 acceptance;
- persistence review scenario -> B5-1 acceptance;
- bounded/resource-constrained behavior -> B5-2 acceptance;
- interrupted session/resume -> B5-3 acceptance;
- B5-4/B5-5 evidence is also available to prove decision/report continuity.

These fixtures run on the real Windows host but are never described as physical production failures.

## Evidence integrity
Each scenario record contains:
- scenario/profile/schema;
- environment type;
- status;
- host fingerprint;
- target/control fingerprint before and after;
- evidence file path, size and SHA-256;
- explicit checks;
- refusal reasons where applicable;
- notes;
- safety contract;
- stable `scenario_sha256`.

The B5-6 summary revalidates:
- scenario profile/schema;
- scenario SHA-256;
- environment classification;
- host fingerprint;
- target before/after claim;
- evidence path/size/hash;
- symlink/reparse refusal;
- required scenario coverage;
- duplicate records;
- safety flags.

Any trust failure fails closed.

## Locked/encrypted candidate
A locked/encrypted scenario may finish as `REFUSED` and still satisfy the acceptance only when:
- a refusal reason is present;
- predecessor evidence proves refusal behavior;
- no unlock attempt is claimed;
- no mount mutation is claimed.

B5-6 does not unlock BitLocker or otherwise modify encrypted volumes.

## Problematic-PC rule
The first B5-6 milestone may pass with `problematic_pc_optional = NOT_RUN`.

This is intentional: a real problematic PC must not be invented, simulated or inferred. When safely available, a separate field run can make it mandatory using `--require-problematic-pc`.

A fixture cannot satisfy this optional real-world case when it is required.

## Safety contract
B5-6:
- is acceptance/evidence only;
- adds no automatic destructive action;
- adds no repair execution authority;
- adds no quarantine execution authority;
- executes no format/reimage;
- adds no registry/boot write authority;
- registers no Windows service or driver;
- does not weaken RR-6 or B5-4 precedence;
- preserves all previous Beta3/Beta4/Beta5 checkpoints.

## Tests
16 dedicated B5-6 tests cover:
- scenario hash construction;
- unknown scenario refusal;
- invalid environment refusal;
- complete required set;
- missing scenario;
- fake real-hardware classification;
- scenario tampering;
- evidence drift;
- duplicate scenario;
- required `NOT_RUN` refusal;
- locked refusal with reason;
- refusal without reason;
- optional problematic-PC behavior;
- mandatory problematic-PC behavior;
- supplied problematic-PC behavior;
- scenario symlink/reparse refusal.

With the accepted 285-test predecessor coverage, B5-6 targets **301 cumulative tests covered**.

## Windows gate
`TEST-V011-BETA5-B56.ps1`:
1. runs the complete accepted B5-5 gate;
2. verifies all predecessor acceptance JSON files required by B5-6;
3. compile-checks B5-6;
4. runs all 16 B5-6 tests;
5. creates the real-host control record;
6. creates five explicitly labeled controlled offline scenario records;
7. builds and verifies the B5-6 acceptance summary;
8. requires the problematic-PC case to remain `NOT_RUN` in this gate;
9. preserves the evidence directory for inspection;
10. verifies no B5-6 Windows service and protected B2 sources unchanged.

## Acceptance rule
B5-6 is frozen only after the authoritative non-elevated Windows gate is fully green.

Passing this milestone does not claim that every possible damaged PC has been repaired successfully. It proves the controlled field-validation framework and a real-host execution baseline. A real problematic-PC case remains a separately identifiable evidence item and must never be fabricated to obtain PASS.
