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
B10-5 — Rescue Continuity
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta10-b104-pass
a23550a0cf31aecdce54d5eca333b3930ca2edc7
```

Latest accepted repository-structure checkpoint:

```text
checkpoint/v011-beta8-repository-hygiene-pass
c33a06d6487115f5ae080edede75f5e63c6bf188
```

Current canonical coverage state:

```text
PARTIAL   4
GAP       0
VERIFIED  2
```

Verified scenarios:

```text
B7-POWERSHELL-001
B7-RANSOMWARE-001
```

`VERIFIED` remains scenario-specific. PowerShell verification is limited to the accepted metadata-only lifecycle-burst detector path and is not a claim of broad script-abuse coverage. Ransomware verification remains limited to the accepted controlled local ransomware-like detector path and is not a claim of broad ransomware-family protection.

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

### B10-1 — Sentinel Proof Mode ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta10-b101-pass
d1ea57abcc69407cf0e17d5ff1e008bcf48ca9af
```

Delivered an evidence-backed Proof Mode that exposes all six security scenarios with exact accepted status, evidence basis, limitation and proof capability. The presentation layer cannot promote coverage, and stale/replayed live evidence fails closed.

Acceptance:

- Windows CI run `35102521115` PASS on exact SHA;
- local Windows PASS on the same SHA;
- `741 passed, 36 warnings` locally;
- baseline report preserves `PARTIAL=5 / GAP=0 / VERIFIED=1`;
- fresh on-demand local ransomware-like proof PASS;
- live controls: positive `24 writes / 18 renames -> DETECTED`, administrative `24 / 18 -> REVIEW_REQUIRED`, benign `2 / 0 -> NO_MATCH`;
- only `B7-RANSOMWARE-001` receives `fresh_proof=true`;
- detector → Security Graph → Incident Correlation binding PASS;
- positive score `10` with accepted signals `BULK_RENAME`, `BULK_REWRITE`, `CANARY_TOUCH`, `ENTROPY_SHIFT`, `EXTENSION_CHURN`;
- `synthetic_fallback_used=false`;
- `broad_protection_claimed=false`;
- no user-file access, file-content collection, personal-data collection, remote access or remediation authority.

B10-1 makes protection evidence visible without overstating coverage and provides the trusted input contract for Attack Story and the later Trust Center UI.

### B10-2 — Attack Story 2.0 ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta10-b102-pass
9882a6f675bcf53e99fee8cd8d6b92286dd3ce66
```

Delivered a deterministic evidence-backed incident narrative built from Security Graph + Incident Correlation. Plain-language and technical views are projections of the same accepted evidence. Missing stages fail closed as `UNKNOWN`; the story never invents an entry point, execution, persistence, network activity or response when those stages are not demonstrated.

Acceptance:

- Windows CI run `35106886446` PASS on exact SHA;
- local Windows PASS on the same SHA;
- `753 passed, 36 warnings` locally;
- live file-control evidence PASS with positive `24 writes / 18 renames`, administrative `24 / 18`, benign `2 / 0`, all cleanup `CLEAN`;
- live Attack Story PASS with exactly two observed stages: `FILE_ACTIVITY` and `DETECTION`;
- `ENTRY_POINT`, `EXECUTION`, `PERSISTENCE`, `NETWORK_ACTIVITY` and `RESPONSE` remain explicitly `UNKNOWN`;
- exactly two evidence-backed claims are emitted;
- detector → Security Graph and Security Graph → Incident Correlation bindings PASS;
- `source_live_control=true` and `synthetic_fallback_used=false`;
- coverage remains `PARTIAL=5 / GAP=0 / VERIFIED=1`;
- `authority_expanded=false` and `broad_protection_claimed=false`;
- local-first privacy boundaries preserve no absolute-path export, no file-content collection, no personal-data collection and no remote access.

B10-2 turns accepted evidence into an understandable incident story while preserving uncertainty instead of filling evidence gaps with inference.

### B10-3 — Live Coverage Expansion I ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta10-b103-pass
b3de7f34cb7ddc381499f34cf68ebd4dd02c0fb8
```

Delivered a safe real-path PowerShell verification using only Windows PowerShell lifecycle metadata. The accepted detector reasons over session density, lifecycle completeness and an explicit administrative suppressor; it never reads command text, script content, event Message, event payload or event Properties.

Acceptance:

- Windows CI run `35115633300` PASS on exact SHA `b3de7f34cb7ddc381499f34cf68ebd4dd02c0fb8`;
- local Windows PASS on the same SHA;
- `760 passed, 36 warnings` locally;
- positive live control: `8` sessions / `8` starts / `8` stops / `8` unique processes -> `DETECTED`;
- administrative live control: `8` sessions / `8` starts / `8` stops / `8` unique processes -> `REVIEW_REQUIRED`;
- benign live control: `1` session / `1` start / `1` stop / `1` unique process -> `NO_MATCH`;
- `B7-POWERSHELL-001` promoted to `VERIFIED` with evidence basis `CONTROLLED_LIVE_POWERSHELL_METADATA_DETECTOR_PATH`;
- `B7-RANSOMWARE-001` remains `VERIFIED`;
- canonical coverage advances to `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- detector → Security Graph and Security Graph → Incident Correlation bindings PASS;
- `synthetic_fallback_used=false`;
- `powershell_content_read=false`;
- `authority_expanded=false` and `broad_powershell_protection_claimed=false`;
- no user-file access, file-content collection, personal-data collection, remote access, network I/O, registry mutation, audit-policy mutation, logging-configuration mutation, credential access, automatic quarantine or remediation authority.

Remaining `PARTIAL` scenarios retain explicit blockers: persistence lacks an accepted harmless live positive detector source; defense-evasion would require protected security-control mutation under the current boundary; DNS/C2 lacks accepted network test authority; credential-access would require sensitive access prohibited by the privacy boundary.

B10-3 expands verified live coverage without reading PowerShell content or widening product authority.

### B10-4 — Safe Response Plan Engine ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta10-b104-pass
a23550a0cf31aecdce54d5eca333b3930ca2edc7
```

Delivered a deterministic planning-only response layer over the accepted Attack Story. For an evidence-backed incident it emits ordered proposed actions with reason, expected impact, required authorities, reversibility, rollback requirement, confirmation requirement and explicit blocker state. Planning never counts as execution and never turns the `RESPONSE` Attack Story stage into observed evidence.

Acceptance:

- Windows CI run `35119030890` PASS on exact SHA `a23550a0cf31aecdce54d5eca333b3930ca2edc7`;
- local Windows PASS on the same SHA;
- `771 passed, 36 warnings` locally;
- local live controls remain clean: ransomware-like `24 writes / 18 renames`, administrative `24 / 18`, benign `2 / 0`;
- exact action order: `PRESERVE_INCIDENT_EVIDENCE`, `PREPARE_CONTAINMENT`, `VERIFY_UNKNOWN_STAGES`, `PREPARE_RESCUE_HANDOFF`;
- containment remains `BLOCKED_AUTHORITY` and explicitly requires user confirmation, target identity binding, quarantine authority, journal binding and rollback binding before any future execution;
- `execution_available=false`, `execution_authorized=false`, `remediation_performed=false`, `system_mutation_performed=false`;
- `authority_expanded=false` and the legacy Guided Resolution execution boundary remains preserved;
- `RESPONSE` remains `UNKNOWN` and `response_stage_claimed_observed=false`;
- plan integrity is bound to a canonical signed core while allowed live wrapper metadata does not invalidate that core; core tampering fails closed;
- coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- `synthetic_fallback_used=false`, `personal_data_collected=false`, `absolute_paths_exported=false`, `file_content_collected=false`, `remote_access=false`.

B10-4 makes BC Sentinel explain what it would do next without silently gaining permission to do it.

### B10-5 — Rescue Continuity (current)

Carry incident IDs, evidence provenance and recommended recovery context from the installed product into accepted portable/rescue workflows. Continuity must remain integrity-bound, local-first and non-executing unless a later milestone separately grants and verifies action authority.

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
