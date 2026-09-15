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
B7-0 — Coverage Ledger Foundation
checkpoint/v011-beta7-b70-pass
cd06f284525b3e0f70c121b6b97833cbf388c9ce
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

### B7-1 — Sentinel Security Graph Foundation — CURRENT

Create a provenance-preserving graph schema linking processes, files, scripts, persistence, network/DNS, detections, evidence and actions.

Required outcomes:
- typed node schema for `PROCESS`, `FILE`, `SCRIPT`, `PERSISTENCE`, `NETWORK`, `DNS`, `DETECTION`, `EVIDENCE`, `ACTION`;
- typed causal/observational edges;
- every node/edge preserves source provenance, source ID, collector and trust classification;
- timestamps, confidence and evidence IDs represented without inventing missing evidence;
- deterministic IDs for ingested observations and relations;
- stable serialization and SHA-256 graph digest;
- duplicate/conflicting IDs fail closed;
- edges to missing nodes and self-loops fail closed;
- every accepted edge has a human-inspectable reason;
- deterministic incident subgraph queries;
- read-only foundation only: no detector/remediation execution authority;
- accepted B7-0 ledger remains unchanged;
- Beta5/Beta6/B7-0 regression remains green;
- Windows CI + local Windows acceptance before checkpoint freeze.

### B7-2 — Incident Correlation Engine

Correlate related observations into one incident using deterministic temporal/causal rules first. Preserve raw evidence and explain every graph edge.

### B7-3 — Confidence Gate

Evaluate recommended actions against severity, evidence strength, confidence, reversibility and potential damage. The gate is inspectable and fail-closed.

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