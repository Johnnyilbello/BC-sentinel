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
B7-5 — Explainable Security
checkpoint/v011-beta7-b75-pass
40f1e9985905ceccc070e8f73d09308a8406d059
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

### B7-5 — Explainable Security ✅ ACCEPTED

Accepted deterministic evidence-grounded explanation layer over B7-1/B7-2/B7-3 outputs.

Accepted outcomes:
- exact graph/correlation/decision digest binding;
- one concise user explanation and one advanced technical explanation from the same evidence;
- every positive claim bound to incident evidence IDs and valid source nodes/edges;
- explicit limitation/uncertainty notes;
- missing evidence never interpreted as proof of safety;
- explanation generation never increases confidence;
- deterministic claim IDs, explanation ID, ordering, serialization and SHA-256 digest;
- `RECOMMEND` remains advisory and explanations grant no execution authority;
- source graph, correlation and decision objects unchanged;
- protected B2 and B7-0/B7-1/B7-2/B7-3/B7-4 foundations unchanged;
- 404 tests passed in local Windows acceptance;
- Windows CI and local Windows acceptance passed.

### B7-6 — Coverage Expansion Campaign — CURRENT

Run controlled scenario-family evaluation across script abuse, persistence, ransomware-like behavior, defense evasion, suspicious network/DNS activity and credential-access indicators. Convert missing scenario-specific evidence into explicit engineering gaps instead of unsupported coverage claims.

Required outcomes:
- consume the accepted B7-0 six-scenario ledger read-only;
- preserve the accepted ledger file unchanged;
- evaluate exactly the six accepted scenario IDs in deterministic order;
- B7-4 synthetic chain evidence may support `PARTIAL` only for script abuse, persistence and suspicious DNS/network scenarios;
- synthetic evidence alone must never produce `VERIFIED` detector coverage;
- ransomware-like, defense-evasion and credential-access families remain explicit `GAP` entries until dedicated harmless detector-path acceptance exists;
- every PARTIAL result carries exact B7-4 report/stage evidence refs plus a remaining coverage gap;
- every GAP carries a concrete reason and next engineering step;
- expected campaign summary is `PARTIAL=3`, `GAP=3`, `VERIFIED=0`;
- deterministic campaign ID, ordering, serialization and SHA-256 campaign digest;
- no real process execution, file writes, network I/O, registry mutation, credential access or remediation execution;
- no execution authority added;
- protected B2 and accepted B7-0/B7-1/B7-2/B7-3/B7-4/B7-5 foundations unchanged;
- Beta5/Beta6/all accepted Beta7 predecessor regression remains green;
- Windows CI + local Windows acceptance required before checkpoint freeze.

### B7-7 — Beta7 Windows Acceptance & Freeze

Acceptance:
- Beta6 predecessor regression green;
- all Beta7 deterministic tests green;
- ledger contains no unsupported positive claims;
- Security Graph/correlation/confidence/explainability outputs remain reproducible;
- safe attack-chain fixtures pass on Windows;
- B7-6 campaign contains explicit gaps and no unsupported VERIFIED claims;
- resource cost measured;
- protected B2 state unchanged unless a separately accepted security milestone explicitly supersedes it;
- final Beta7 checkpoint freeze.

## Reasoning policy

- **Extra High:** confidence/authority boundaries, attack-chain acceptance, any remediation expansion, final release gate.
- **High:** graph/correlation implementation, coverage ledger, tests, explainability and metrics.

Milestone-by-milestone only. Do not skip acceptance gates.
