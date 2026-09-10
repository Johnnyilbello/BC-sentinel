# BC Sentinel — Roadmap checkpoint v0.11.0-beta.2

## Accepted baseline
`v0.11.0-beta.1` is the frozen Windows baseline for this milestone.

The complete one-command Windows gate reached:

```text
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

with 609 pytest tests green and enforced service-performance gates green. Reboot persistence remains deferred to final-roadmap validation.

## v0.11.0-beta.2 — Service Integration, Retrospective Hunting & Root Cause

Beta2 is split so the durable hunting/query layer can be validated before changing the Protection Service runtime, and the FULL-only service source can be inspected before any integration patch is attempted.

### Checkpoint A — Indexed Retrospective Hunting — accepted
- preserve the Beta1 `EdrTelemetryStore` and `EdrPipeline` unchanged;
- create indexed SHA-256/domain/IP/path hunting over already-persisted telemetry;
- bounded, cursor-based timeline pagination;
- exact indicator matching by default to reduce false positives;
- incident → telemetry evidence navigation;
- bounded process root-cause view for incident PIDs;
- bounded retention/max-event administration primitives;
- no automatic process kill/delete/host isolation;
- no mandatory cloud dependency.

Checkpoint A accepted on Windows with 20 targeted pytest tests green and `tools.v011_beta2_hunting_acceptance` green.

Windows test isolation rule: targeted pytest execution uses a unique per-run `--basetemp` so a transient lock on pytest's shared `pytest-current` cleanup path cannot convert an otherwise green security test run into a false failure. This does not suppress or relax any test.

### Checkpoint B0 — Protection Service integration preflight — accepted
- `EdrServiceBridge` established as a transport-independent service-owned EDR facade;
- explicit separation between authenticated read operations and privileged retention mutation;
- HIGH incident notification contract remains non-destructive;
- EDR ingestion errors are contained so enrichment cannot stop the existing protection path;
- AST-only inspection captured the authoritative FULL `ProtectionRuntime` and `ProtectionServiceCore` structure;
- B0 modified no FULL Protection Service source.

Windows B0 evidence:
- 17 targeted tests PASS;
- source preflight PASS;
- `ProtectionRuntime.__init__`, `_on_event`, `status`, `ProtectionServiceCore.dispatch_validated` and IPC/event anchors discovered;
- authoritative pre-integration `protection_service_core.py` SHA-256: `29bc05622b61c0723a81a25fc658570f06b9ff96ad0460f9e6fab4e10af5f4d7`.

### Checkpoint B1a — Service-owned EDR runtime integration — current
Scope is deliberately limited before changing the authenticated IPC protocol:
- instantiate one service-owned `EdrServiceBridge` in `ProtectionRuntime`;
- use the accepted ProgramData EDR path and bounded retention configuration;
- feed the existing `ProtectionRuntime._on_event` SecurityEvent stream into the EDR adapter without duplicate collectors;
- expose EDR runtime status inside the existing service status response;
- EDR ingestion remains fail-contained and cannot stop the protection pipeline;
- no new process kill, delete, quarantine, isolation or containment behavior;
- exact B0 source SHA is required before first mutation;
- patch is AST-verified, idempotent, backed up and atomically promoted;
- legacy Beta1/Checkpoint A EDR tests remain mandatory.

B1a does **not** yet claim authenticated EDR IPC, Security Center Inbox merge, service restart persistence or performance acceptance.

### Checkpoint B1b — Authenticated EDR IPC + Security Center integration
Starts only after B1a is green on the authoritative FULL tree.

Required scope:
- authenticated Named Pipe read endpoints for timeline, process tree, incidents, incident evidence, root cause and IOC hunts;
- bounded query pagination enforced server-side;
- retention administration classified as privileged and routed through the existing protected/UAC authorization path;
- qualified EDR incidents surface in the existing Security Center Inbox without autonomous remediation;
- strict per-operation payload schemas and unknown-field rejection;
- no arbitrary RPC, generic method dispatch, pickle/object deserialization or shell execution surface.

### Checkpoint B2 — Service-native live/restart/performance acceptance
- build fresh Protection Service and UAC Broker;
- verify real service-owned event ingestion from native collectors;
- verify authenticated EDR IPC over the production Named Pipe;
- restart service and prove EDR store/hunting indexes persist;
- prove Security Center Inbox visibility for qualified test incidents;
- rerun Beta1 full regression and enforced service performance thresholds `25 / 10 / 250` unchanged.

### Beta2 final acceptance
Beta2 is not accepted until Checkpoint A, B0, B1a, B1b and B2 are green on the authoritative FULL Windows tree. Beta1 full regression remains mandatory.

## Safety invariants carried forward
- no single heuristic HIGH;
- no heuristic-only destructive response;
- no automatic file delete;
- no automatic process kill;
- no automatic host isolation;
- signed IOC precedence and v0.10 Web Protection safeguards remain unchanged;
- shared-IP/CDN safeguards remain fail-closed;
- no HTTPS MITM/root CA/TLS interception;
- no mandatory cloud runtime dependency;
- no weakening of the accepted `25 / 10 / 250` service performance thresholds.

## Parallel future macro-area — BC Sentinel Rescue & Recovery
The product roadmap includes a dedicated recovery track for severely compromised PCs where installed Windows cannot reliably install or execute BC Sentinel. It progresses through RR-0 Architecture & Safety, RR-1 Portable, RR-2 Rescue USB, RR-3 Offline Threat Scanner, RR-4 Repair Engine, RR-5 Safe Data Rescue and RR-6 Integrity Verification & Recovery Certification.

This track must reduce reimaging/formatting to a last resort without ever declaring a system recovered when integrity cannot be demonstrated. It reuses accepted detection/intelligence primitives but remains operationally independent from the installed Protection Service.

Codex policy for this track:
- **Reasoning: Extra High** for architecture, security boundaries, offline/boot parsing, repair primitives and integrity certification;
- **Reasoning: High** for ordinary implementation and test/integration work after the security design is frozen;
- milestone-by-milestone only, with automatic tests, compromised-PC scenarios and measurable acceptance gates; existing protections and security/performance thresholds may not be weakened to pass.
