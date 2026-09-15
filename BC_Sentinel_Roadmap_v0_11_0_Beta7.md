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
B7-4 — Attack-Chain Acceptance Harness
checkpoint/v011-beta7-b74-pass
d836aef24480d21e6631c1fe0dac640c7862e7ec
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

### B7-1 — Sentinel Security Graph Foundation ✅ ACCEPTED

Accepted provenance-preserving graph schema linking processes, files, scripts, persistence, network/DNS, detections, evidence and actions.

### B7-2 — Incident Correlation Engine ✅ ACCEPTED

Accepted deterministic incident grouping over the read-only Security Graph.

Accepted outcomes:
- validated B7-1 Security Graph input only;
- source graph digest preserved and source graph unchanged;
- explicit graph relations preserve incident membership;
- shared evidence IDs and explicit correlation keys correlate only within configured windows;
- temporal proximity alone never correlates;
- every correlation link is explained;
- deterministic incident IDs, stable serialization and SHA-256 correlation digest;
- every source node/edge represented exactly once;
- malformed/duplicate/cross-incident bindings fail closed;
- protected B2, B7-0 and B7-1 foundations unchanged;
- Windows CI and local Windows acceptance passed.

### B7-3 — Confidence Gate ✅ ACCEPTED

Accepted deterministic advisory gate over B7-2 correlation results.

Accepted outcomes:
- exact source graph/correlation digest binding;
- explicit severity, evidence strength, confidence, reversibility and damage dimensions;
- deterministic `RECOMMEND`, `REVIEW_REQUIRED`, `BLOCKED_INSUFFICIENT_EVIDENCE` outcomes;
- missing/unsupported evidence and absent/insufficient confidence fail closed;
- high/unknown damage and insufficient reversibility require human review;
- confidence is never inferred from missing evidence;
- stable decision IDs/serialization/SHA-256 digest;
- `RECOMMEND` is advisory only and never grants execution authority;
- tampered authority outputs fail validation;
- accepted B7-0/B7-1/B7-2 foundations and protected B2 state unchanged;
- Windows CI and local Windows acceptance passed.

### B7-4 — Attack-Chain Acceptance Harness ✅ ACCEPTED

Accepted harmless end-to-end synthetic acceptance chain over B7-1/B7-2/B7-3.

Accepted outcomes:
- synthetic in-memory fixtures only; no real process execution, file write, network I/O, registry mutation or remediation execution;
- accepted chain: `PROCESS -> SCRIPT -> PERSISTENCE -> DNS -> DETECTION`;
- deterministic stage order, graph construction, incident correlation and report serialization;
- detection latency derived exactly from fixture timestamps;
- end-to-end `RECOMMEND`, `REVIEW_REQUIRED` and `BLOCKED_INSUFFICIENT_EVIDENCE` gate cases;
- advisory interruption eligibility never grants execution authority;
- stable SHA-256 report digest;
- source graph/correlation unchanged;
- protected B2 and B7-0/B7-1/B7-2/B7-3 foundations unchanged;
- 394 tests passed in local Windows acceptance;
- Windows CI and local Windows acceptance passed.

### B7-5 — Explainable Security — CURRENT

Generate two evidence-grounded explanations for significant incidents: a user-level explanation and an advanced technical explanation. No invented certainty.

Required outcomes:
- consume only validated B7-1 Security Graph, B7-2 correlation and B7-3 Confidence Gate outputs;
- bind explanation output to exact graph, correlation and decision digests;
- generate one concise user explanation and one advanced technical explanation from the same accepted evidence;
- every positive claim must bind to incident evidence IDs and valid source node/edge IDs;
- include explicit limitation/uncertainty notes; missing evidence must never be interpreted as proof of safety;
- explanation generation must never increase or infer confidence beyond source observations/decision values;
- deterministic claim IDs, explanation ID, ordering, serialization and SHA-256 digest;
- `RECOMMEND` remains advisory and explanation text must preserve the no-authority boundary;
- reject tampered source digests, unbound evidence claims, confidence amplification and authority expansion;
- source graph, correlation and decision objects remain unchanged;
- accepted B7-0/B7-1/B7-2/B7-3/B7-4 foundations remain unchanged;
- protected B2 state remains unchanged from accepted Beta6;
- Beta5/Beta6/all accepted Beta7 predecessor regression remains green;
- Windows CI + local Windows acceptance required before checkpoint freeze.

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
