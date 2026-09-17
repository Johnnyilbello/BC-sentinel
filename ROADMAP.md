# BC Sentinel — Canonical Roadmap

This is the **only roadmap source of truth** for BC Sentinel. Accepted engineering checkpoints are immutable. Documentation may advance after an engineering freeze, but accepted checkpoints never move.

## Current state

```text
Beta5   COMPLETE / FROZEN
Beta6   COMPLETE / FROZEN
Beta7   COMPLETE / FROZEN
Beta8   COMPLETE / FROZEN
Beta9   COMPLETE / FROZEN
Beta10  IN PROGRESS — FINAL ACCEPTANCE
```

Current milestone:

```text
B10-9 — Windows Competitive Acceptance & Freeze
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta10-b108-pass
aa0c2b4e4b79381f9a20a5d69e99e972dee46971
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

- Exact Windows CI + local acceptance first; immutable accepted checkpoint second.
- Missing evidence fails closed; synthetic evidence alone cannot support `VERIFIED`.
- Predictions are advisory and never evidence.
- Security exercises use harmless fixtures, temporary resources, simulations, disposable/offline targets and explicit opt-in.
- Scope is not widened while repairing acceptance failures.
- Product claims may never exceed accepted evidence.
- Beta10 milestones must improve at least one measurable customer-value pillar; feature count alone is not success.
- B10-9 `competitive` means conformance to the internal Beta10 value/safety contract; it is **not** an external market-superiority claim.

### Authority boundary

General product authority remains:

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

B10-6 introduced one explicit exception only: reversible quarantine + rollback inside an explicitly initialized disposable temporary workspace, with operator confirmation, exact target binding, tamper-evident journal and rollback. It does **not** grant broad Home execution or autonomous remediation.

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

**Status: IN PROGRESS — FINAL ACCEPTANCE**

Goal: turn BC Sentinel from a capable security engine into a differentiated security product for professionals, technicians and small organizations by making protection demonstrable, incidents understandable, response safe/reversible and operational impact measurable.

### Value pillars

1. **Protection Proof** — show exactly what is proven on this machine, when it was last proven and what remains partial.
2. **Attack Story** — turn accepted evidence into an ordered incident narrative without inventing missing stages.
3. **Safe Response** — show proposed action, expected impact, required authority and rollback before execution.
4. **Rescue Continuity** — preserve incident/evidence continuity between normal Windows and portable/rescue workflows.
5. **Low-Noise Operation** — false positives, latency, resource use and user interruptions are product KPIs.
6. **Local-First Privacy** — basic proof and reasoning remain local-first with explicit privacy boundaries.

### B10-0 — Value Foundation + Competitive Contract ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b100-pass
8f9b315eb3137f461dce1f679af32d8a9d680990
```

- Windows CI + local PASS on exact SHA;
- `731 passed, 36 warnings` locally;
- six value pillars and ten milestones fixed;
- Beta9 baseline preserved at `PARTIAL=5 / GAP=0 / VERIFIED=1`;
- no authority or protection-claim expansion.

### B10-1 — Sentinel Proof Mode ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b101-pass
d1ea57abcc69407cf0e17d5ff1e008bcf48ca9af
```

Evidence-backed Proof Mode exposes all six security scenarios with exact accepted status, evidence basis, limitation and proof capability. Presentation cannot promote coverage and stale/replayed evidence fails closed.

Acceptance included `741 passed, 36 warnings`, fresh ransomware-like on-demand proof, detector → Security Graph → Incident Correlation binding and no remediation/privacy-boundary expansion.

### B10-2 — Attack Story 2.0 ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b102-pass
9882a6f675bcf53e99fee8cd8d6b92286dd3ce66
```

Deterministic evidence-backed incident narrative. Plain-language and technical views project the same accepted evidence; missing stages remain `UNKNOWN` and are never invented.

Acceptance included `753 passed, 36 warnings`, two observed stages (`FILE_ACTIVITY`, `DETECTION`), five explicit `UNKNOWN` stages and no broad protection claim.

### B10-3 — Live Coverage Expansion I ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b103-pass
b3de7f34cb7ddc381499f34cf68ebd4dd02c0fb8
```

Safe real-path PowerShell verification using lifecycle metadata only. No command text, script content, event Message, payload or Properties are read.

Acceptance:

- Windows CI + local PASS on exact SHA;
- `760 passed, 36 warnings` locally;
- positive `8/8/8/8 -> DETECTED`;
- administrative `8/8/8/8 -> REVIEW_REQUIRED`;
- benign `1/1/1/1 -> NO_MATCH`;
- PowerShell promoted to `VERIFIED`;
- coverage advanced to `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- no network, credential, remediation or privileged-mutation authority.

### B10-4 — Safe Response Plan Engine ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b104-pass
a23550a0cf31aecdce54d5eca333b3930ca2edc7
```

Planning-only response layer over Attack Story. Proposed actions expose reason, expected impact, required authority, reversibility, rollback and confirmation before execution.

Acceptance included `771 passed, 36 warnings`; containment remained `BLOCKED_AUTHORITY`; `execution_available=false`; `RESPONSE` stayed `UNKNOWN`; coverage remained `PARTIAL=4 / GAP=0 / VERIFIED=2`.

### B10-5 — Rescue Continuity ✅ INTEGRATED / IMMUTABLE SOURCE

```text
checkpoint/v011-beta10-b105-pass
259fdbf988e442366f0deb3a07b3de248cf309ba
```

Carries incident IDs, evidence provenance and recommended recovery context from the installed product into accepted portable/rescue workflows while remaining integrity-bound, local-first and non-executing.

- Windows CI run `35121043861` PASS on source SHA;
- source remains immutable in the later accepted regression chain;
- target binding remains required and no rescue write/execution authority is implied.

### B10-6 — Reversible Response Pilot ✅ INTEGRATED / IMMUTABLE SOURCE

```text
checkpoint/v011-beta10-b106-pass
79293c641d1ecf5e1ce8d1fa313b9ea4b03f3868
```

Introduced one deliberately narrow response action: reversible quarantine of one regular file inside an explicitly initialized disposable temporary workspace. Requires exact operator confirmation, target identity/hash binding, tamper-evident local journal and rollback.

- Windows CI run `35217808582` PASS;
- `803 passed, 36 warnings` in CI;
- harmless exercise `QUARANTINED -> ROLLED_BACK`;
- no broad Home execution, automatic remediation, delete, repair, process termination, trust mutation, privileged mutation or rescue write authority.

### B10-7 — Live Coverage Expansion II + Operational Impact ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b107-pass
2428817e99b9e0969fc00e4c76e383a1004ba26c
```

Measured the operational cost and low-noise behavior of the accepted live PowerShell metadata path and evaluated all remaining safe live-coverage candidates without forcing unsafe authority expansion.

Acceptance:

- Windows CI run `35221374534` PASS on exact SHA;
- local Windows PASS on the same exact SHA;
- `818 passed, 36 warnings`;
- local p95 wall `0.5493 ms`;
- local p95 CPU `15.625 ms`;
- local max RSS delta `0.003906 MiB`;
- local user interruptions `0`;
- false-positive controls PASS (`DETECTED` / `REVIEW_REQUIRED` / `NO_MATCH`);
- coverage remains honestly `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- no new authority expansion and no broad protection claim.

### B10-8 — Trust Center Product Integration ✅ ACCEPTED / FROZEN

```text
checkpoint/v011-beta10-b108-pass
aa0c2b4e4b79381f9a20a5d69e99e972dee46971
```

Integrated Protection Proof, Attack Story boundaries, coverage limitations, privacy boundaries, Safe Response, the narrow reversible-response pilot, Rescue Continuity and Operational Impact into one coherent read-only Trust Center/UI.

Acceptance:

- Windows CI run `35227868672` PASS on exact SHA `aa0c2b4e4b79381f9a20a5d69e99e972dee46971`;
- local Windows PASS on the same exact SHA;
- CI: `830 passed, 38 warnings`;
- local: `830 passed, 38 warnings in 79.60s`;
- Trust Center exposes `6` scenarios and `6` accepted capabilities;
- application shell has `7` pages with Trust Center navigation enabled;
- no horizontal overflow at `560`, `680`, `960`, `1440` px in CI and local smoke tests;
- local operational measurement: p95 wall `0.3276 ms`, p95 CPU `0.0 ms`, max RSS delta `0.003906 MiB`, user interruptions `0`;
- coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- presentation cannot promote coverage;
- general response execution remains disabled;
- reversible-response scope remains exactly `DISPOSABLE_TEMP_WORKSPACE_ONLY`;
- no new authority expansion and no broad protection claim.

B10-8 makes the accepted evidence, limits, privacy and response boundaries understandable in the product without changing what the engine is allowed to claim or execute.

### B10-9 — Windows Competitive Acceptance & Freeze 🚧 CURRENT / FREEZE CANDIDATE

B10-9 is the final Beta10 gate. It adds no protection capability. It independently composes and rechecks the entire accepted Beta10 value/safety contract before an immutable final freeze can be created.

Acceptance requirements:

- B10-8 immutable checkpoint identity must be exact and all accepted predecessor paths must remain unchanged;
- full Beta5→Beta10 regression must pass on Windows;
- fresh live PowerShell positive / administrative / benign controls must pass;
- fresh Operational Impact measurement must remain within accepted latency/CPU/RAM/user-interruption budgets;
- Trust Center UI smoke must pass at all accepted widths with zero horizontal overflow;
- harmless B10-6 pilot must again demonstrate `QUARANTINED -> ROLLED_BACK` with journal and exact narrow authority;
- all six B10-0 value pillars must be demonstrated by accepted evidence;
- final coverage must remain `PARTIAL=4 / GAP=0 / VERIFIED=2` unless a separately accepted live detector milestone changes it;
- general response execution must remain disabled;
- Rescue Continuity must remain non-executing and local-first;
- no new B10-9 authority, broad-protection claim, presentation-driven coverage promotion or external market-superiority claim is permitted;
- exact Windows CI **and local acceptance on the same final SHA** are required before `checkpoint/v011-beta10-b109-pass` may be created and Beta10 may be marked `COMPLETE / FROZEN`.

Current engineering branch:

```text
feature/v011-beta10-b109-windows-competitive-acceptance-freeze
```

The branch is a freeze candidate only. Beta10 remains `IN PROGRESS` until the final exact-commit local acceptance succeeds.

## Longer-term programs

Future work after Beta10 may include broader self-healing, adaptive local intelligence, deception/canary expansion, sandboxing/dynamic analysis, network IDS/IPS, identity protection, fleet management and production/commercial packaging. None is an accepted protection claim until its own milestone passes.

## Repository/documentation policy

- `ROADMAP.md` is the single roadmap file.
- `README.md` is the public landing page, not a second roadmap.
- `SECURITY.md` contains security/disclosure guidance.
- `STABLE-RELEASE.md` documents the separately promoted stable channel.
- Historical engineering evidence remains recoverable from Git history and immutable checkpoint refs.
- Every future milestone/status change updates this file in the same development cycle.
