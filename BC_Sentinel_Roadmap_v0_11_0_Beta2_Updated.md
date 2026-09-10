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

B1a does not claim authenticated EDR IPC, Inbox merge, native-live ingestion, restart persistence or performance acceptance.

### Checkpoint B1b-preflight — Authenticated IPC structure discovery — current
Because `protection_protocol.py` and the production IPC client are FULL-only, B1b starts with a non-mutating protocol preflight.

Required discovery:
- exact `protection_protocol.py` SHA;
- `validate_request` structure;
- `PRIVILEGED_OPERATIONS` and operation/schema constants;
- `ProtectionServiceCore._authorize` and `dispatch_validated` branches/calls;
- production client IPC surface when present;
- accepted B1a service-core SHA must still match before any protocol mutation.

This preflight may not modify protocol, dispatcher, authorization or client source.

### Checkpoint B1b — Authenticated EDR IPC + Security Center integration
Starts only after B1b-preflight is green.

Required scope:
- authenticated Named Pipe read endpoints for timeline, process tree, incidents, incident evidence, root cause and IOC hunts;
- bounded query pagination enforced server-side;
- strict per-operation payload schemas and unknown-field rejection;
- `edr_update_retention` classified as privileged and routed through the existing UAC/admin authorization path;
- qualified HIGH EDR incidents surfaced in the existing Security Center Inbox without autonomous remediation;
- no arbitrary RPC, generic method dispatch, pickle/object deserialization or shell execution surface.

### Checkpoint B2 — Service-native live/restart/performance acceptance
- fresh Protection Service and UAC Broker build;
- real service-owned native event ingestion;
- authenticated EDR IPC over production Named Pipe;
- restart persistence for store/hunting indexes;
- Security Center Inbox visibility for qualified test incidents;
- Beta1 full regression and performance thresholds `25 / 10 / 250` unchanged.

### Beta2 final acceptance
Beta2 is not accepted until Checkpoint A, B0, B1a, B1b-preflight, B1b and B2 are green on the authoritative FULL Windows tree. Beta1 full regression remains mandatory.

## Safety invariants carried forward
- no single heuristic HIGH;
- no heuristic-only destructive response;
- no automatic file delete, process kill or host isolation;
- signed IOC precedence and v0.10 Web Protection safeguards unchanged;
- shared-IP/CDN safeguards remain fail-closed;
- no HTTPS MITM/root CA/TLS interception;
- no mandatory cloud runtime dependency;
- no weakening of service performance thresholds `25 / 10 / 250`.

## Parallel future macro-area — BC Sentinel Rescue & Recovery
The roadmap includes the dedicated recovery track for severely compromised PCs where installed Windows cannot reliably install or execute BC Sentinel: RR-0 Architecture & Safety, RR-1 Portable, RR-2 Rescue USB, RR-3 Offline Threat Scanner, RR-4 Repair Engine, RR-5 Safe Data Rescue and RR-6 Integrity Verification & Recovery Certification.

The track aims to make reimaging/formatting the last resort, but a machine is never declared recovered when integrity cannot be demonstrated. It reuses accepted detection/intelligence primitives while remaining operationally independent from the installed Protection Service.

Codex policy:
- **Reasoning: Extra High** for architecture, security boundaries, offline/boot parsing, repair primitives and integrity certification;
- **Reasoning: High** for ordinary implementation and test/integration after the security design is frozen;
- milestone-by-milestone only, with automatic tests, compromised-PC scenarios and measurable acceptance gates; existing protections and thresholds may not be weakened to pass.
