# BC Sentinel v0.11.0-beta.7 — B7-1 Implementation Status

Status: **CLOSED / ACCEPTED — WINDOWS CI PASS + LOCAL DEVICE PASS**

Accepted implementation commit:

```text
c75697b25c63e59bdfc2ad32374c4232c607fea0
```

Accepted checkpoint:

```text
checkpoint/v011-beta7-b71-pass
```

Accepted predecessor:

```text
B7-0 — Coverage Ledger Foundation
checkpoint/v011-beta7-b70-pass
cd06f284525b3e0f70c121b6b97833cbf388c9ce
Windows CI: PASS
Local Windows acceptance: PASS
```

## Acceptance summary

B7-1 is accepted on Windows with:

- compile gate PASS;
- Beta5 + Beta6 + B7-0 predecessor regression + B7-1 deterministic suite: **361 passed, 36 warnings**;
- B7-0 coverage ledger self-check PASS;
- Security Graph semantic/determinism self-check PASS;
- Windows CI run `34974953956`: SUCCESS;
- local Windows acceptance: PASS.

Local evidence is recorded in:

```text
BC_SENTINEL_V011_BETA7_B71_LOCAL_DEVICE_ACCEPTANCE_2026-09-15.md
```

## Scope

B7-1 introduces the first read-only **Sentinel Security Graph** data model. It links observations and evidence into a deterministic, provenance-preserving incident graph without changing detector behavior or remediation authority.

Supported node classes:

```text
PROCESS
FILE
SCRIPT
PERSISTENCE
NETWORK
DNS
DETECTION
EVIDENCE
ACTION
```

Supported relation classes:

```text
SPAWNED
EXECUTED
ACCESSED
CREATED
MODIFIED
PERSISTED_VIA
RESOLVED_TO
CONNECTED_TO
TRIGGERED
SUPPORTED_BY
ACTION_ON
OBSERVED_WITH
```

Every accepted node/edge can carry:

- source provenance;
- source ID;
- collector identity;
- provenance trust classification;
- timestamp;
- evidence IDs;
- confidence when available;
- typed attributes;
- a human-inspectable reason on every edge.

## Determinism / integrity rules

B7-1 provides:

- deterministic IDs for observation nodes;
- deterministic IDs for relations;
- stable node/edge ordering;
- stable JSON serialization;
- SHA-256 digest of the canonical graph;
- idempotent re-ingest of an identical object;
- fail-closed conflicting duplicate IDs;
- fail-closed missing edge endpoints;
- fail-closed self-loops;
- validation of timestamps, confidence, evidence IDs and provenance;
- deterministic incident subgraph queries;
- exact in-memory round-trip serialization.

Accepted graph self-check digest:

```text
10380636f532f5aaf477fd9d179214c212955e9088c87e0c219d655b09eac775
```

## Safety boundary

```text
read_only = true
execution_authority_added = false
automatic_quarantine = false
automatic_repair = false
automatic_restore = false
general_home_execution_authorized = false
DELETE = false
REPAIR = false
TERMINATE_PROCESS = false
TRUST/ALLOWLIST mutation = false
privileged/system mutation = false
```

The Security Graph does not execute processes, contact networks, change trust state, mutate files, quarantine, repair, restore or terminate anything.

## Predecessor freeze

The accepted gate verified that:

- protected B2 paths are unchanged from the accepted Beta6 checkpoint;
- the B7-0 coverage ledger JSON, validator and deterministic tests are unchanged from `checkpoint/v011-beta7-b70-pass`.

## Next milestone

Proceed from:

```text
checkpoint/v011-beta7-b71-pass
```

Next roadmap milestone:

```text
B7-2 — Incident Correlation Engine
```

B7-1 remains frozen. No later work may rewrite the accepted checkpoint.