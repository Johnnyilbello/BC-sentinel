# BC Sentinel v0.11.0-beta.7 — B7-1 Implementation Status

Status: **IMPLEMENTED — WINDOWS CI + LOCAL DEVICE ACCEPTANCE PENDING**

Active branch:

```text
feature/v011-beta7-b71-security-graph
```

Accepted predecessor:

```text
B7-0 — Coverage Ledger Foundation
checkpoint/v011-beta7-b70-pass
cd06f284525b3e0f70c121b6b97833cbf388c9ce
Windows CI: PASS
Local Windows acceptance: PASS
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

The B7-1 local acceptance explicitly checks that:

- protected B2 paths are unchanged from the accepted Beta6 checkpoint;
- the B7-0 coverage ledger JSON, validator and deterministic tests are unchanged from `checkpoint/v011-beta7-b70-pass`.

## Automated gate

Windows CI runs:

1. compile for B7-0/B7-1 modules and tests;
2. Beta5 + Beta6 + B7-0 predecessor regression plus B7-1 deterministic tests;
3. B7-0 coverage ledger self-check;
4. B7-1 Security Graph self-check;
5. deterministic graph-digest and no-authority-expansion assertions.

## Local Windows acceptance

After CI is green, run from normal PowerShell in the repository root:

```powershell
git fetch origin; git checkout feature/v011-beta7-b71-security-graph; git pull --ff-only origin feature/v011-beta7-b71-security-graph; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B71.ps1" -ConfirmSecurityGraphAcceptance
```

Expected final line:

```text
BC SENTINEL v0.11.0-beta.7 B7-1 SENTINEL SECURITY GRAPH FOUNDATION - PASS
```

Do not create `checkpoint/v011-beta7-b71-pass` until both Windows CI and the local-device gate pass.
