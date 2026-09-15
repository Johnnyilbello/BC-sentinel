# BC Sentinel v0.11.0-beta.7 — B7-2 Implementation Status

Status: **IMPLEMENTED — WINDOWS CI + LOCAL DEVICE ACCEPTANCE PENDING**

Active branch:

```text
feature/v011-beta7-b72-incident-correlation
```

Accepted predecessor:

```text
B7-1 — Sentinel Security Graph Foundation
checkpoint/v011-beta7-b71-pass
c75697b25c63e59bdfc2ad32374c4232c607fea0
Windows CI: PASS
Local Windows acceptance: PASS
```

## Scope

B7-2 introduces a deterministic, conservative **Incident Correlation Engine** on top of the accepted read-only B7-1 Security Graph.

It groups Security Graph observations into incidents only when there is explicit evidence for doing so:

1. an existing Security Graph relation;
2. shared evidence IDs inside the configured correlation time window;
3. collector-provided explicit `correlation_keys` inside the configured correlation time window.

Temporal proximity by itself never correlates two observations.

## Correlation output

Each incident records:

- deterministic incident ID;
- exact member node IDs;
- exact source graph edge IDs;
- start/end timestamps derived from member observations;
- explanatory correlation links.

Each correlation link records:

- deterministic link ID;
- source and target node IDs;
- correlation rule;
- human-inspectable reason;
- observed time and time delta;
- supporting evidence IDs;
- supporting explicit correlation keys when applicable;
- source graph edge binding when the link comes from an existing graph relation.

## Integrity and determinism

B7-2 enforces:

- validated B7-1 Security Graph input only;
- source graph digest preserved before/after correlation;
- no source graph mutation;
- every source node assigned exactly once;
- every source graph edge represented exactly once;
- deterministic incident/link IDs;
- stable ordering and stable JSON serialization;
- SHA-256 digest of correlation output;
- exact round-trip serialization;
- malformed explicit correlation keys fail closed;
- invalid duplicate/cross-incident bindings fail closed;
- temporal correlation rules cannot exceed the configured time window;
- every accepted correlation link has an explanation.

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

B7-2 does not execute detectors, mutate files, contact networks, quarantine, repair, restore, terminate processes or change trust state.

## Predecessor freeze

The local acceptance explicitly verifies:

- protected B2 paths remain unchanged from accepted Beta6;
- B7-0 coverage ledger core files remain unchanged;
- B7-1 Security Graph module/tests remain unchanged from `checkpoint/v011-beta7-b71-pass`.

## Automated gate

Windows CI runs:

1. compile B7-0/B7-1/B7-2 modules and tests;
2. Beta5 + Beta6 + B7-0 + B7-1 regression plus B7-2 deterministic tests;
3. B7-0 coverage ledger self-check;
4. B7-1 Security Graph self-check;
5. B7-2 Incident Correlation self-check;
6. explicit determinism/no-authority-expansion assertions.

## Local Windows acceptance

After CI is green, run from normal PowerShell in the repository root:

```powershell
git fetch origin; git checkout feature/v011-beta7-b72-incident-correlation; git pull --ff-only origin feature/v011-beta7-b72-incident-correlation; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B72.ps1" -ConfirmIncidentCorrelationAcceptance
```

Expected final line:

```text
BC SENTINEL v0.11.0-beta.7 B7-2 INCIDENT CORRELATION ENGINE - PASS
```

Do not create `checkpoint/v011-beta7-b72-pass` until both Windows CI and the local-device acceptance pass.
