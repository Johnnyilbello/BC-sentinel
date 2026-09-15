# BC Sentinel v0.11.0-beta.7 — B7-2 Implementation Status

Status: **CLOSED / ACCEPTED**

Accepted implementation commit:

```text
32bf6563eccc7f03c26e08afe6fcb58cf207cd8d
```

Frozen checkpoint:

```text
checkpoint/v011-beta7-b72-pass
32bf6563eccc7f03c26e08afe6fcb58cf207cd8d
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

## Accepted output contract

Each incident records deterministic membership, source edge bindings, incident timing and explanatory correlation links. Every accepted link records its rule, reason, endpoints, time delta and supporting evidence or explicit correlation keys.

Accepted invariants include:

- validated B7-1 Security Graph input only;
- exact source graph digest preserved before/after correlation;
- no source graph mutation;
- every source node assigned exactly once;
- every source graph edge represented exactly once;
- deterministic incident/link IDs;
- stable ordering and JSON serialization;
- SHA-256 correlation-result digest;
- exact round-trip serialization;
- malformed explicit correlation keys fail closed;
- invalid duplicate/cross-incident bindings fail closed;
- temporal correlation rules respect the configured time window;
- temporal proximity alone is never sufficient;
- every accepted correlation link has an explanation.

## Acceptance evidence

Local Windows gate:

```text
372 passed, 36 warnings
Compile gate: PASS
Predecessor + B7-2 deterministic gate: PASS
B7-0 coverage ledger self-check: PASS
B7-1 Security Graph self-check: PASS
Incident Correlation determinism + safety contract: PASS
BC SENTINEL v0.11.0-beta.7 B7-2 INCIDENT CORRELATION ENGINE - PASS
```

Correlation digest:

```text
780f2bb2dc91932d63dabb729d635fbf0f1dbe58896ed9df686aca73d0ac52cb
```

Windows CI on the exact accepted implementation commit also completed successfully.

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

Protected B2 state, B7-0 Coverage Ledger and B7-1 Security Graph accepted foundations remained unchanged.

## Next milestone

Proceed only from:

```text
checkpoint/v011-beta7-b72-pass
```

Next milestone: **B7-3 — Confidence Gate**.
