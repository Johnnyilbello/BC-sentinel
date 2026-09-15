# BC Sentinel — Roadmap v0.11.0-beta.7

## Detection Coverage & Incident Intelligence

### Frozen predecessor

Beta7 starts only from the accepted Beta6 final built-artifact checkpoint:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

Beta6 remains immutable. Beta7 must not weaken the accepted quarantine/restore boundaries, fail-closed behavior, protected B2 state, portable artifact contract or explicit-operator-action requirements.

Latest accepted Beta7 checkpoint:

```text
B7-2 — Incident Correlation Engine
checkpoint/v011-beta7-b72-pass
32bf6563eccc7f03c26e08afe6fcb58cf207cd8d
Windows CI: PASS
Local Windows acceptance: PASS
```

## Goal

Move BC Sentinel from a collection of accepted protection/recovery capabilities toward **measurable attack coverage and connected incident intelligence**.

Beta7 must answer three questions with evidence:

1. Which attack scenarios are currently covered?
2. Which signals belong to the same incident?
3. How confident is BC Sentinel before recommending or authorizing an action?

No capability may be advertised as covered only because a detector or UI element exists.

## Non-negotiable safety contract

Beta7 does not automatically gain new remediation authority.

```text
automatic quarantine          = false
automatic repair              = false
automatic restore             = false
general Home execution        = false
DELETE                        = false
REPAIR                        = false
TERMINATE_PROCESS             = false
TRUST/ALLOWLIST mutation      = false
privileged/system mutation    = false
```

Any future authority expansion requires a dedicated milestone, explicit acceptance criteria and a new Windows acceptance gate.

## Milestones

### B7-0 — Coverage Ledger Foundation ✅ ACCEPTED

Accepted machine-readable attack coverage ledger required by the global roadmap.

Accepted outcomes:
- versioned JSON ledger in the repository;
- deterministic schema/semantic validator;
- stable `scenario_id` contract;
- ATT&CK technique/sub-technique fields;
- `PLANNED`, `PARTIAL`, `VERIFIED` and `GAP` states;
- positive coverage claims require current build provenance and evidence references;
- untested scenarios cannot silently appear as successful;
- duplicate scenario IDs rejected;
- deterministic summary metrics;
- no detector, remediation or execution behavior changed;
- Beta5/Beta6 regression green.

### B7-1 — Sentinel Security Graph Foundation ✅ ACCEPTED

Accepted provenance-preserving graph schema linking processes, files, scripts, persistence, network/DNS, detections, evidence and actions.

Accepted outcomes:
- typed node and relation classes;
- source provenance, source ID, collector and trust classification preserved;
- timestamps, confidence and evidence IDs preserved;
- deterministic node/relation IDs;
- stable JSON serialization and SHA-256 graph digest;
- conflicting duplicates, missing endpoints and self-loops fail closed;
- every graph relation requires a human-inspectable reason;
- deterministic subgraph queries and exact round-trip serialization;
- no detector/remediation execution authority;
- B7-0 foundation unchanged;
- Beta5/Beta6/B7-0 regression green;
- Windows CI + local Windows acceptance passed.

### B7-2 — Incident Correlation Engine ✅ ACCEPTED

Accepted deterministic incident grouping over the read-only Security Graph.

Accepted outcomes:
- only validated B7-1 `SecurityGraph` inputs are consumed;
- exact source graph digest preserved and source graph never mutated;
- explicit graph relations keep their endpoints in the same incident;
- shared evidence IDs may correlate only within the configured temporal window;
- explicit collector correlation keys may correlate only within the configured temporal window;
- temporal proximity alone never correlates observations;
- every correlation link records rule, reason, endpoints, timestamps and supporting evidence/keys;
- deterministic incident IDs, ordering, serialization and SHA-256 correlation digest;
- every source node assigned exactly once;
- every source graph edge represented exactly once;
- malformed correlation keys and invalid/duplicate/cross-incident bindings fail closed;
- correlation output round-trips deterministically;
- B7-0/B7-1 foundations and protected B2 state remain unchanged;
- no detector/remediation execution authority;
- Beta5/Beta6/B7-0/B7-1 regression green;
- Windows CI + local Windows acceptance passed.

### B7-3 — Confidence Gate — CURRENT

Evaluate recommended actions against severity, evidence strength, confidence, reversibility and potential damage. The gate must be deterministic, inspectable and fail closed. No remediation authority is gained merely because a recommendation receives a high confidence score.

Required outcomes:
- consume accepted B7-2 incident/correlation output without mutating it;
- deterministic evaluation inputs and output schema;
- explicit severity, evidence strength, confidence, reversibility and potential-damage dimensions;
- clear separation between `RECOMMEND`, `REVIEW_REQUIRED` and `BLOCKED/INSUFFICIENT_EVIDENCE` style outcomes;
- missing/invalid evidence fails closed;
- confidence is never inferred from absent evidence;
- every decision includes machine-readable reasons and human-inspectable rationale;
- no automatic quarantine/repair/restore/process termination/trust mutation authority;
- accepted B7-0/B7-1/B7-2 foundations remain unchanged;
- protected B2 state remains unchanged;
- Beta5/Beta6/B7-0/B7-1/B7-2 regression remains green;
- Windows CI + local Windows acceptance required before checkpoint freeze.

### B7-4 — Attack-Chain Acceptance Harness

Add harmless, controlled end-to-end attack-chain simulations and measure observation, detection, correlation, interruption eligibility, evidence quality and timing.

### B7-5 — Explainable Security

Generate two evidence-grounded explanations for significant incidents: a user-level explanation and an advanced technical explanation. No invented certainty.

### B7-6 — Coverage Expansion Campaign

Run controlled scenario families across script abuse, persistence, ransomware-like behavior, defense evasion, suspicious network activity and credential-access indicators. Convert missing coverage into explicit engineering gaps.

### B7-7 — Beta7 Windows Acceptance & Freeze

Acceptance:
- Beta6 predecessor regression green;
- all Beta7 deterministic tests green;
- ledger contains no unsupported positive claims;
- Security Graph/correlation/confidence outputs remain reproducible;
- safe attack-chain fixtures pass on Windows;
- resource cost measured;
- protected B2 state unchanged unless a separately accepted security milestone explicitly supersedes it;
- final Beta7 checkpoint freeze.

## Reasoning policy

- **Extra High:** confidence/authority boundaries, attack-chain acceptance, any remediation expansion, final release gate.
- **High:** graph/correlation implementation, coverage ledger, tests, explainability and metrics.

Milestone-by-milestone only. Do not skip acceptance gates.
