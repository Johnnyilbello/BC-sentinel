# BC Sentinel — Roadmap checkpoint v0.11.0-beta.2

## Accepted baseline
`v0.11.0-beta.1` is the frozen Windows baseline for this milestone.

The complete one-command Windows gate reached:

```text
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

with 609 pytest tests green and enforced service-performance gates green. Reboot persistence remains deferred to final-roadmap validation.

## v0.11.0-beta.2 — Service Integration, Retrospective Hunting & Root Cause

Beta2 is split so durable hunting can be validated before changing the Protection Service, and every FULL-only mutation is preceded by a non-mutating structural preflight.

### Checkpoint A — Indexed Retrospective Hunting — accepted
- indexed SHA-256/domain/IP/path hunting over persisted telemetry;
- bounded cursor pagination and time windows;
- incident → evidence navigation and bounded process root cause;
- bounded retention administration primitives;
- no automatic process kill/delete/host isolation and no mandatory cloud dependency.

Windows evidence: 20 targeted pytest tests PASS and `tools.v011_beta2_hunting_acceptance` PASS.

### Checkpoint B0 — Protection Service integration preflight — accepted
- `EdrServiceBridge` established as transport-independent service-owned EDR facade;
- read/privileged operation separation and non-destructive Inbox notification contract;
- EDR ingestion failure containment;
- authoritative FULL `ProtectionRuntime`/`ProtectionServiceCore` structure discovered without mutation.

Windows evidence: 17 targeted tests PASS; preflight PASS; original service-core SHA-256 `29bc05622b61c0723a81a25fc658570f06b9ff96ad0460f9e6fab4e10af5f4d7`.

### Checkpoint B1a — Service-owned EDR runtime integration — accepted
- one `EdrServiceBridge` owned by `ProtectionRuntime`;
- existing `_on_event` SecurityEvent stream feeds EDR without duplicate collectors;
- EDR runtime state exposed through existing service `status()`;
- ingestion remains fail-contained and non-destructive;
- exact source-SHA guard, AST verification, backup, atomic promotion and idempotence enforced.

Windows evidence:
- 33 targeted pytest tests PASS;
- B1a imports PASS;
- runtime patch and post-patch verification PASS;
- pre-patch SHA `29bc05622b61c0723a81a25fc658570f06b9ff96ad0460f9e6fab4e10af5f4d7`;
- accepted B1a service-core SHA `9b3af57236b68de1ed5f7e23808d3d409ad2a64499a484696819467b9d5f0ca3`;
- backup `protection_service_core.py.pre-v011-beta2-b1a.bak` created.

### Checkpoint B1b-preflight — Authenticated IPC structure discovery — accepted
Windows evidence:
- 13 targeted pytest tests PASS;
- B1b preflight PASS;
- accepted protocol SHA-256 `cffcdaaea7850f2e0d995a75e14f18471bef9e920b57860b7ad68ce01e43090d`;
- accepted B1a service-core SHA-256 `9b3af57236b68de1ed5f7e23808d3d409ad2a64499a484696819467b9d5f0ca3`;
- accepted production client SHA-256 `6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1`;
- `validate_request`, `PRIVILEGED_OPERATIONS`, `_authorize` and `dispatch_validated` discovered;
- no protocol, dispatcher, authorization or client source was modified by the preflight.

### Checkpoint B1b — Authenticated EDR IPC + Security Center integration — accepted
Implemented and accepted scope:
- authenticated Named Pipe read operations for EDR status, timeline, process tree, incidents, incident evidence, root cause and IOC hunts;
- bounded server-side query payloads with strict per-operation field allowlists and unknown-field rejection;
- `edr_update_retention` classified as privileged and forced through the existing `_authorize`/UAC-admin path;
- qualified persistent HIGH EDR incidents projected into the existing `pending_threats` Security Center source as review-only records;
- existing production client source remains unchanged and SHA-guarded;
- transactional FULL patch with exact SHA guards, backups, post-write verification and rollback protection;
- no arbitrary RPC, generic runtime method dispatch, pickle/object deserialization, shell execution or autonomous remediation added.

Windows evidence:
- 44 targeted pytest tests PASS;
- B1b preflight, patch verification, B1a preservation, compile/import and B1b acceptance all PASS;
- accepted post-B1b protocol SHA-256 `2e39ec0422f820e107832b3ba20c62c103ea15cc99639159ea2ec1be211505b1`;
- accepted post-B1b service-core SHA-256 `d5395dc2bb086941796703910143a0598e8fd4da36e53c19e2a910030498fe46`;
- production client remains `6910eb42f6e7c5ba4d87b1f1533dfacff99483fbf4ffb06810595effa66cc9d1`;
- automatic process kill, file delete and host isolation remain false.

### Checkpoint B2 — Service-native live/restart/performance acceptance — accepted
Accepted scope:
- full frozen Beta1 regression families remain green;
- fresh Protection Service and UAC Broker build from standard-user PowerShell;
- real Repair/readiness and administrator gate;
- enforced service performance thresholds `idle <=25%`, `IPC >=10/s`, `storm <=250%` remain unchanged;
- authenticated EDR reads over the production Named Pipe;
- privileged `edr_update_retention` accepted only in administrator context with unchanged effective values;
- harmless native `%TEMP%` `.tmp` marker acquired by the realtime filesystem-observation path and discoverable through exact `edr_hunt`;
- qualified harmless HIGH test incident visible through the existing Security Center `pending_threats` projection as review-only;
- real SCM service restart followed by readiness and persistence verification;
- standard-user authenticated EDR reads preserved while direct privileged retention remains rejected;
- standard-user → UAC broker acceptance and Beta1 EDR regression remain green;
- no reboot is claimed by B2; reboot persistence remains a final-roadmap validation gate.

#### Final B2 V6 Windows evidence
The authoritative FULL Windows run completed the repaired non-executable filesystem-observation path with:
- patcher preflight: **7 tests PASS** before touching production source;
- temporary V1/V4 marker diagnostics removed from production source using exact pre-instrumentation backups;
- final non-executable observation separation applied with static-scan scope unchanged;
- focused final V6 regression suite: **58 tests PASS**;
- strict deterministic source-lineage v3: **PASS**;
- accepted service SHA-256 `4be64d52f1e6a735bcd4deefdcaf4293cd3bb268d26748f1e3b0cd21c05886ae`;
- accepted realtime SHA-256 `aa8c657182329e7a020271bdfa69a9caebe89386fe67c7c5fda1073445c3ca1a`;
- final Protection Service build + UAC Broker + firewall build: **PASS**;
- Named Pipe self-test: **PASS**;
- final binary SHA-256 `22fc0330e1efc9dab4335ed37a67f30565fb7e5ac9e76cdd5141ed6627d31fc1`;
- frozen administrator live/performance phase: **PASS**;
- measured steady-state performance: **idle 5.00%**, **IPC 31.00 requests/s**, **benign storm 9.63%**;
- native `%TEMP%` B2 marker: **PASS**;
- Beta1 EDR regression: **PASS**, including persistence, stable event dedup, flood guard, queryability and throughput floor;
- automatic destructive action remains disabled in the accepted runtime path: no automatic process kill, file delete or host isolation.

Final gate:

```text
BC SENTINEL v0.11.0-beta.2 B2 NONEXEC OBSERVATION V6 - PASS
```

Frozen recovery checkpoint:

```text
checkpoint/v011-beta2-b2-pass-v6
b943f1ee550ad5c2bee3d8753962d5971c212381
```

### Beta2 final acceptance — accepted
Checkpoint A, B0, B1a, B1b-preflight, B1b and B2 are green on the authoritative FULL Windows tree. Beta1 regression remains preserved. The v0.11.0-beta.2 service-integration/hunting milestone is therefore closed.

Reboot persistence is still deferred to final-roadmap validation and is not implied by the B2 PASS.

## Safety invariants carried forward
- no single heuristic HIGH;
- no heuristic-only destructive response;
- no automatic file delete, process kill or host isolation;
- signed IOC precedence and v0.10 Web Protection safeguards unchanged;
- shared-IP/CDN safeguards remain fail-closed;
- no HTTPS MITM/root CA/TLS interception;
- no mandatory cloud runtime dependency;
- no weakening of service performance thresholds `25 / 10 / 250`.

## Next milestone — BC Sentinel Rescue & Recovery / RR-0 Architecture & Safety
RR-0 is the next implementation milestone. It defines the security boundary for recovery of severely compromised PCs where installed Windows cannot reliably install or execute BC Sentinel.

RR-0 must be completed before Portable/USB/offline scanning or repair implementation begins.

Required RR-0 outputs:
- explicit trust model for running from compromised Windows versus trusted external/boot media;
- read-only-by-default evidence acquisition and immutable session manifest;
- filesystem/device discovery model with no blind destructive repair;
- quarantine/repair transaction model with rollback and provenance;
- offline registry/boot/startup inspection boundaries;
- integrity verification strategy that can refuse to certify a machine as recovered;
- containment of symlink/reparse-point/path traversal/device alias risks;
- privilege/elevation model and operator-confirmation boundaries;
- measurable resource ceilings and bounded concurrency;
- deterministic audit/log schema with correlation IDs and exact failure stage/reason;
- threat-model tests and compromised-PC simulation scenarios;
- explicit rule that formatting/reimaging remains available when integrity cannot be demonstrated.

RR-0 acceptance requires architecture + tests/spec evidence only; it must not silently introduce destructive repair actions into production.

Codex policy for RR-0:
- **Reasoning: Extra High** for architecture, security boundaries, offline/boot parsing, repair primitives and integrity certification;
- **Reasoning: High** only after those boundaries are frozen and implementation becomes ordinary test/integration work.

## Parallel future Rescue & Recovery track
After RR-0: RR-1 Portable, RR-2 Rescue USB, RR-3 Offline Threat Scanner, RR-4 Repair Engine, RR-5 Safe Data Rescue and RR-6 Integrity Verification & Recovery Certification.

The track aims to make reimaging/formatting the last resort, but a machine is never declared recovered when integrity cannot be demonstrated. It reuses accepted detection/intelligence primitives while remaining operationally independent from the installed Protection Service.
