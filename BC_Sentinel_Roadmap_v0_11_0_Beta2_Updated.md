# BC Sentinel — Roadmap checkpoint v0.11.0-beta.2

## Accepted baseline
`v0.11.0-beta.1` is the frozen Windows baseline for this milestone.

The complete one-command Windows gate reached:

```text
BC SENTINEL v0.11.0-beta.1 - ALL GATES PASS
```

with 609 pytest tests green and enforced service-performance gates green. Reboot persistence remains deferred to final-roadmap validation.

## v0.11.0-beta.2 — Service Integration, Retrospective Hunting & Root Cause

Beta2 is split into two checkpoints so the durable hunting/query layer can be validated before changing the Protection Service runtime.

### Checkpoint A — Indexed Retrospective Hunting
- preserve the Beta1 `EdrTelemetryStore` and `EdrPipeline` unchanged;
- create indexed SHA-256/domain/IP/path hunting over already-persisted telemetry;
- bounded, cursor-based timeline pagination;
- exact indicator matching by default to reduce false positives;
- incident → telemetry evidence navigation;
- bounded process root-cause view for incident PIDs;
- bounded retention/max-event administration primitives;
- no automatic process kill/delete/host isolation;
- no mandatory cloud dependency.

Checkpoint A acceptance command:

```powershell
.\UPDATE-TEST-V011-BETA2-CHECKPOINT-A.bat
```

Required final line:

```text
BC SENTINEL v0.11.0-beta.2 CHECKPOINT A - PASS
```

Windows test isolation rule: targeted pytest execution uses a unique per-run `--basetemp` so a transient lock on pytest's shared `pytest-current` cleanup path cannot convert an otherwise green security test run into a false failure. This does not suppress or relax any test.

### Checkpoint B — Protection Service Integration
- Protection Service owns the EDR telemetry store lifecycle;
- native process/file/network/DNS/download/persistence events continuously feed the EDR pipeline;
- authenticated Named Pipe IPC endpoints for timeline, process tree, incidents and hunts;
- bounded query pagination enforced server-side;
- protected retention administration through existing privileged/UAC workflows;
- qualified EDR incidents surface in Security Center Inbox;
- service restart/recovery preserves the EDR store and hunting indexes;
- no autonomous destructive EDR response.

### Beta2 final acceptance
Beta1 full regression remains mandatory. Beta2 is not accepted until Checkpoint A and Checkpoint B are both green on the authoritative FULL Windows tree, including service-native live evidence and performance regression checks.

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
The product roadmap now includes a dedicated recovery track for severely compromised PCs where installed Windows cannot reliably install or execute BC Sentinel. It progresses through RR-0 Architecture & Safety, RR-1 Portable, RR-2 Rescue USB, RR-3 Offline Threat Scanner, RR-4 Repair Engine, RR-5 Safe Data Rescue and RR-6 Integrity Verification & Recovery Certification.

This track must reduce reimaging/formatting to a last resort without ever declaring a system recovered when integrity cannot be demonstrated. It reuses accepted detection/intelligence primitives but remains operationally independent from the installed Protection Service.

Codex policy for this track:
- **Reasoning: Extra High** for architecture, security boundaries, offline/boot parsing, repair primitives and integrity certification;
- **Reasoning: High** for ordinary implementation and test/integration work after the security design is frozen;
- milestone-by-milestone only, with automatic tests, compromised-PC scenarios and measurable acceptance gates; existing protections and security/performance thresholds may not be weakened to pass.
