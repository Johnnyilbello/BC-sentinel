# BC Sentinel — Canonical Roadmap

This is the **only roadmap source of truth** for BC Sentinel. Accepted engineering checkpoints are immutable. Documentation may advance after an engineering freeze, but accepted checkpoints never move.

## Current state

```text
Beta5   COMPLETE / FROZEN
Beta6   COMPLETE / FROZEN
Beta7   COMPLETE / FROZEN
Beta8   COMPLETE / FROZEN
Beta9   COMPLETE / FROZEN
Beta10  IN PROGRESS
```

Current milestone:

```text
B10-1 — Sentinel Proof Mode
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta10-b100-pass
8f9b315eb3137f461dce1f679af32d8a9d680990
```

Latest accepted repository-structure checkpoint:

```text
checkpoint/v011-beta8-repository-hygiene-pass
c33a06d6487115f5ae080edede75f5e63c6bf188
```

Current canonical coverage state:

```text
PARTIAL   5
GAP       0
VERIFIED  1
```

Verified scenario:

```text
B7-RANSOMWARE-001
```

`VERIFIED` remains limited to the accepted controlled live local ransomware-like detector path. It is not a claim of broad ransomware-family protection.

## Engineering contract

- Exact Windows CI + local acceptance first; immutable checkpoint second.
- Missing evidence fails closed; synthetic evidence alone cannot support `VERIFIED`.
- Predictions are advisory and never evidence.
- Security exercises use harmless fixtures, temporary resources, simulations, disposable/offline targets and explicit opt-in.
- Scope is not widened while repairing acceptance failures.
- Product claims may never exceed accepted evidence.
- Beta10 milestones must improve at least one measurable customer-value pillar; feature count alone is not success.

### Authority boundary

Unless a later explicit milestone expands authority and passes acceptance:

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

## Accepted foundations

### Beta5 — Technician / recovery hardening

**COMPLETE / FROZEN** — hardened recovery workflows, hostile-target assessment, evidence packaging, controlled real-PC acceptance and portable technician foundations.

### Beta6 — Technician UX and guided resolution

**COMPLETE / FROZEN**

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

Windows UI, Home security overview, Smart Scan UX, threat cards, guided-resolution foundations and portable GUI, while preserving no-automatic-remediation boundaries.

### Beta7 — Detection Coverage & Incident Intelligence

**COMPLETE / FROZEN**

```text
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Coverage ledger, Security Graph, Incident Correlation, Confidence Gate, attack-chain acceptance, explainable security and explicit coverage accounting.

### Beta8 — Verified Detection & Predictive Defense

**COMPLETE / FROZEN**

```text
checkpoint/v011-beta8-b87-pass
3c32157dd0c6bb852438319766a9345b0b9f5f1e
```

Deterministic ransomware-like, defense-evasion and credential-access detector evidence plus attack prediction. Beta8 intentionally remained `PARTIAL=6 / GAP=0 / VERIFIED=0` because detector evidence was synthetic/in-memory.

## Beta9 — Real Windows Telemetry & Detector Verification

**COMPLETE / FROZEN**

Final checkpoint:

```text
checkpoint/v011-beta9-b94-pass
cc32c2c31ebb9b863624632a38175ec5825430e4
```

Accepted line:

- B9-0 Windows telemetry foundation — `checkpoint/v011-beta9-b90-pass`
- B9-1 bounded metadata reader — `checkpoint/v011-beta9-b91-pass`
- B9-2 harmless event-to-incident acceptance — `checkpoint/v011-beta9-b92-pass`
- B9-3 live false-positive controls / coverage decisions — `checkpoint/v011-beta9-b93-pass`
- B9-4 Windows final acceptance & freeze — `checkpoint/v011-beta9-b94-pass`

Final Beta9 acceptance:

- Windows CI + local PASS on exact SHA `cc32c2c31ebb9b863624632a38175ec5825430e4`;
- `721 passed, 36 warnings`;
- local live pipeline `5.586691 s`;
- deterministic core PASS;
- privacy / no-remediation / no-privileged-mutation boundaries PASS;
- ransomware-like controlled local detector path promoted to `VERIFIED`;
- final coverage `PARTIAL=5 / GAP=0 / VERIFIED=1`.

## Beta10 — Verifiable Protection, Explainable Response & Product Value

**Status: IN PROGRESS**

Goal: turn BC Sentinel from a capable security engine into a differentiated security product for professionals, technicians and small organizations by making protection demonstrable, incidents understandable, response safe/reversible and operational impact measurable.

### Value pillars

1. **Protection Proof** — show exactly what is proven on this machine, when it was last proven and what remains partial.
2. **Attack Story** — turn accepted evidence into an ordered incident narrative without inventing missing stages.
3. **Safe Response** — show proposed action, expected impact, required authority and rollback before execution.
4. **Rescue Continuity** — preserve incident/evidence continuity between normal Windows and portable/rescue workflows.
5. **Low-Noise Operation** — false positives, latency, resource use and user interruptions are product KPIs.
6. **Local-First Privacy** — basic proof and reasoning remain local-first with explicit privacy boundaries.

### B10-0 — Value Foundation + Competitive Contract ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta10-b100-pass
8f9b315eb3137f461dce1f679af32d8a9d680990
```

Acceptance:

- Windows CI run `35100878497` PASS on exact SHA;
- local Windows PASS on the same SHA;
- `731 passed, 36 warnings` locally;
- deterministic value contract PASS;
- `pillar_count=6`, `milestone_count=10`;
- Beta9 baseline preserved at `PARTIAL=5 / GAP=0 / VERIFIED=1`;
- `authority_expanded=false`;
- `protection_claim_expanded=false`.

B10-0 establishes the rule that Beta10 is judged by measurable trust, clarity, recovery continuity, noise and safety rather than by feature count.

### B10-1 — Sentinel Proof Mode (current)

Build a customer-visible proof layer over accepted evidence. It must expose per-scenario status (`VERIFIED`, `PARTIAL`, `GAP`), evidence basis, last accepted verification, explicit limitation, and a safe on-demand proof path where technically supported. Proof Mode may not convert a scenario to `VERIFIED` by UI presentation alone.

### B10-2 — Attack Story 2.0

Create a user-readable incident story from Security Graph + Incident Correlation with evidence-backed stages, confidence, timestamps and explicit unknowns.

### B10-3 — Live Coverage Expansion I

Target safe real-path verification for additional scenarios, prioritizing PowerShell and persistence. Promotion requires harmless positive, administrative and benign controls plus accepted provenance.

### B10-4 — Safe Response Plan Engine

Generate deterministic proposed-response plans with action, reason, expected impact, authority requirement, reversibility and blocked-state explanations. No automatic execution at this milestone.

### B10-5 — Rescue Continuity

Carry incident IDs, evidence provenance and recommended recovery context from the installed product into accepted portable/rescue workflows.

### B10-6 — Reversible Response Pilot

Introduce only narrowly scoped, explicitly authorized and rollback-capable response actions that pass dedicated safety acceptance. No broad autonomous remediation.

### B10-7 — Live Coverage Expansion II + Operational Impact

Attempt remaining safe live detector verification and measure detection latency, false-positive controls, CPU/RAM cost and user-interruption budget.

### B10-8 — Trust Center Product Integration

Integrate Protection Proof, Attack Story, coverage limitations, privacy boundaries and accepted response capabilities into a coherent customer-facing Trust Center/UI.

### B10-9 — Windows Competitive Acceptance & Freeze

Full regression, exact-commit Windows CI/local acceptance, measured value KPIs, privacy/authority review and immutable Beta10 freeze.

## Longer-term programs

Future work after Beta10 may include broader self-healing, adaptive local intelligence, deception/canary expansion, sandboxing/dynamic analysis, network IDS/IPS, identity protection, fleet management and production/commercial packaging. None is an accepted protection claim until its own milestone passes.

## Repository/documentation policy

- `ROADMAP.md` is the single roadmap file.
- `README.md` is the public landing page, not a second roadmap.
- `SECURITY.md` contains security/disclosure guidance.
- `STABLE-RELEASE.md` documents the separately promoted stable channel.
- Historical engineering evidence remains recoverable from Git history and immutable checkpoint refs.
- Every future milestone/status change updates this file in the same development cycle.
