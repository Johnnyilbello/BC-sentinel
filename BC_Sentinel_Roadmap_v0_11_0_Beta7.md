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
B7-6 — Coverage Expansion Campaign
checkpoint/v011-beta7-b76-pass
1bd66f4f9e55313388e871e26c6a35d55a3dbb20
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

### B7-6 — Coverage Expansion Campaign ✅ ACCEPTED

Accepted conservative scenario-family coverage campaign over the six B7-0 ledger entries.

Accepted outcomes:
- accepted B7-0 ledger preserved read-only;
- exactly six scenario IDs evaluated in deterministic order;
- B7-4 synthetic evidence supports `PARTIAL` only for script abuse, persistence and suspicious DNS/network;
- ransomware-like, defense-evasion and credential-access remain explicit `GAP` entries;
- exact campaign summary: `PARTIAL=3`, `GAP=3`, `VERIFIED=0`;
- no synthetic evidence promoted to VERIFIED detector coverage;
- every PARTIAL/GAP carries evidence or explicit engineering follow-up;
- deterministic campaign digest and stable round-trip;
- no real process execution, file writes, network I/O, registry mutation, credential access or remediation execution;
- no execution authority added;
- protected B2 and accepted B7-0/B7-1/B7-2/B7-3/B7-4/B7-5 foundations unchanged;
- 413 tests passed in local Windows acceptance;
- Windows CI and local Windows acceptance passed.

### B7-7 — Beta7 Windows Acceptance & Freeze — CURRENT

Final Beta7 release gate. This milestone does not add detector or remediation authority; it proves that the complete accepted Beta7 intelligence stack remains reproducible, conservative and compatible with the frozen Beta6 portable boundary.

Required outcomes:
- start only from `checkpoint/v011-beta7-b76-pass` / `1bd66f4f9e55313388e871e26c6a35d55a3dbb20`;
- Beta5 + Beta6 + complete Beta7 deterministic regression green on Windows;
- B7-0 ledger remains valid with no unsupported positive claims;
- B7-1 Security Graph remains deterministic and round-trip stable;
- B7-2 Incident Correlation remains deterministic, explained and conservative;
- B7-3 Confidence Gate keeps `RECOMMEND`, `REVIEW_REQUIRED`, `BLOCKED_INSUFFICIENT_EVIDENCE` and never grants authority;
- B7-4 harmless attack-chain remains synthetic/non-executing and preserves exact stage order;
- B7-5 Explainable Security remains evidence-bound, uncertainty-aware and does not amplify confidence;
- B7-6 campaign remains exactly `PARTIAL=3`, `GAP=3`, `VERIFIED=0` with no unsupported VERIFIED claims;
- accepted Beta6 B6-7 portable contract remains unchanged (`onedir`, windowed, portable, explicit operator action, no installer/service/driver/network/cloud requirement);
- protected B2 state remains unchanged from the accepted Beta6 checkpoint;
- final synthetic pipeline resource cost is measured (wall time + peak traced memory) without contaminating the deterministic core digest;
- final core snapshot is reproducible across repeated evaluation;
- automatic quarantine/repair/restore, DELETE, REPAIR, process termination, trust mutation and privileged system mutation remain false;
- exact-head Windows CI and local Windows acceptance must both pass before final checkpoint freeze;
- after both gates pass, create `checkpoint/v011-beta7-b77-pass` on the exact tested code SHA and never move it.

## Reasoning policy

- **Extra High:** confidence/authority boundaries, attack-chain acceptance, any remediation expansion, final release gate.
- **High:** graph/correlation implementation, coverage ledger, tests, explainability and metrics.

Milestone-by-milestone only. Do not skip acceptance gates.
