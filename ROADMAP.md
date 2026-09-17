# BC Sentinel — Canonical Roadmap

This is the **only roadmap source of truth** for BC Sentinel. Accepted engineering checkpoints are immutable. Documentation may advance after an engineering freeze, but accepted checkpoints never move.

## Current state

```text
Beta5   COMPLETE / FROZEN
Beta6   COMPLETE / FROZEN
Beta7   COMPLETE / FROZEN
Beta8   COMPLETE / FROZEN
Beta9   COMPLETE / FROZEN
Beta10  COMPLETE / FROZEN
Beta11  IN PROGRESS
```

Current milestone:

```text
B11-0 — Windows Productization Foundation
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta10-b109-pass
89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9
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
- Beta10 value/safety boundaries remain inherited by Beta11 unless a later milestone explicitly earns new authority.
- Productization may not silently promote detection coverage or remediation authority.
- Installer, signing, service, driver, auto-update or release claims require their own accepted evidence before they can be presented as available.

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

Final Beta9 acceptance:

- Windows CI + local PASS on exact SHA `cc32c2c31ebb9b863624632a38175ec5825430e4`;
- `721 passed, 36 warnings`;
- local live pipeline `5.586691 s`;
- deterministic core PASS;
- privacy / no-remediation / no-privileged-mutation boundaries PASS;
- ransomware-like controlled local detector path promoted to `VERIFIED`;
- final coverage `PARTIAL=5 / GAP=0 / VERIFIED=1`.

## Beta10 — Verifiable Protection, Explainable Response & Product Value

**Status: COMPLETE / FROZEN**

Final checkpoint:

```text
checkpoint/v011-beta10-b109-pass
89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9
```

Beta10 made protection demonstrable, incidents explainable, response planning bounded/reversible where accepted, rescue continuity explicit and operational impact measurable.

### Beta10 accepted line

- B10-0 Value Foundation + Competitive Contract — `checkpoint/v011-beta10-b100-pass`
- B10-1 Sentinel Proof Mode — `checkpoint/v011-beta10-b101-pass`
- B10-2 Attack Story 2.0 — `checkpoint/v011-beta10-b102-pass`
- B10-3 Live Coverage Expansion I — `checkpoint/v011-beta10-b103-pass`
- B10-4 Safe Response Plan Engine — `checkpoint/v011-beta10-b104-pass`
- B10-5 Rescue Continuity — `checkpoint/v011-beta10-b105-pass`
- B10-6 Reversible Response Pilot — `checkpoint/v011-beta10-b106-pass`
- B10-7 Live Coverage Expansion II + Operational Impact — `checkpoint/v011-beta10-b107-pass`
- B10-8 Trust Center Product Integration — `checkpoint/v011-beta10-b108-pass`
- B10-9 Windows Competitive Acceptance & Freeze — `checkpoint/v011-beta10-b109-pass`

Final Beta10 acceptance:

- Windows CI run `35230121430` PASS on exact SHA `89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9`;
- local Windows PASS on the same exact SHA;
- CI: `845 passed, 38 warnings in 89.33s`;
- local: `845 passed, 38 warnings in 89.40s`;
- all `6/6` Beta10 value pillars demonstrated by accepted evidence;
- all `10` Beta10 milestones accounted for;
- final coverage `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- verified scenarios `B7-POWERSHELL-001` and `B7-RANSOMWARE-001`;
- local p95 wall `0.3633 ms`, p95 CPU `0.0 ms`, max RSS delta `0.003906 MiB`, user interruptions `0`;
- Trust Center `7` pages with zero horizontal overflow at accepted widths;
- reversible-response pilot completed `QUARANTINED -> ROLLED_BACK` with `4` journal records;
- reversible-response scope `DISPOSABLE_TEMP_WORKSPACE_ONLY`;
- Rescue Continuity non-executing and local-first;
- general response execution disabled;
- presentation cannot promote coverage;
- no new B10-9 authority expansion, broad-protection claim, credential access, network I/O or cloud requirement.

Beta10 is **COMPLETE / FROZEN** at immutable checkpoint `checkpoint/v011-beta10-b109-pass`.

## Beta11 — Windows Productization & Release Readiness

**Status: IN PROGRESS**

Goal: convert the accepted Beta10 source into a Windows product that can be built, installed, started, upgraded, rolled back and uninstalled predictably on real PCs without weakening the accepted security, privacy or evidence boundaries.

### Productization pillars

1. **Canonical Desktop Entry** — one supported Windows entrypoint with explicit runtime identity and predictable startup behavior.
2. **Reproducible Artifact** — release artifacts bind to an immutable source checkpoint, tool versions and SHA-256 manifest.
3. **Install Lifecycle** — install, repair, upgrade and uninstall behavior is explicit and limited to product-owned resources.
4. **First-Run Health** — startup can explain missing/broken runtime prerequisites before protection claims are relied upon.
5. **Release Provenance** — checkpoint, artifact, signing state and exact CI/local evidence are traceable and factual.
6. **Safe Upgrade Recovery** — persistent product data/configuration survive accepted upgrades and rollback remains bounded.

### B11-0 — Windows Productization Foundation 🚧 CURRENT

Contract-only milestone. It freezes the Beta10 source identity and defines what Beta11 must prove before BC Sentinel may be treated as a distributable Windows product.

Acceptance requirements:

- exact source must remain `checkpoint/v011-beta10-b109-pass` / `89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9`;
- accepted Beta10 source paths may not be changed by B11-0;
- canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- the two verified scenarios remain unchanged;
- six productization pillars and ten Beta11 milestones must be deterministic and machine-verifiable;
- B11-0 must not claim an installer, signed artifact, service, driver, autostart or auto-update as available;
- core startup remains local-first with no network/cloud requirement introduced by the foundation;
- general remediation/privileged authority remains unchanged;
- full Beta5→Beta11 regression must pass on Windows;
- exact Windows CI + local acceptance on the same SHA are required before `checkpoint/v011-beta11-b110-pass` may be created.

### Planned Beta11 line

- **B11-1 — Canonical Desktop Entry + Runtime Identity** — replace historical/technician launch ambiguity with one product entrypoint and explicit runtime/source identity.
- **B11-2 — Reproducible Windows Onedir Build** — build the accepted product UI into an integrity-manifested Windows artifact.
- **B11-3 — Installer / Uninstaller Contract** — define install scope, product-owned resources, uninstall safety and elevation boundaries before execution.
- **B11-4 — First-Run Health + Repair Guidance** — read-only health diagnosis and bounded repair guidance without hidden mutation.
- **B11-5 — Persistent App Data + Logs + Quarantine Model** — define ownership, permissions and lifecycle of persistent product data.
- **B11-6 — Upgrade / Rollback + Config Migration** — deterministic migration and rollback rules across accepted product versions.
- **B11-7 — Release Provenance + Signing Readiness** — artifact provenance, factual signing state, hashes and release evidence; signing is never implied when absent.
- **B11-8 — Clean-PC Install / Upgrade / Uninstall Acceptance** — real Windows lifecycle acceptance on clean/disposable systems.
- **B11-9 — Windows Release Candidate Acceptance & Freeze** — full regression and immutable release-candidate freeze.

Current engineering branch:

```text
feature/v011-beta11-b110-productization-foundation
```

## Longer-term programs

Future work after the current accepted roadmap may include broader self-healing, adaptive local intelligence, deception/canary expansion, sandboxing/dynamic analysis, network IDS/IPS, identity protection and fleet management. None is an accepted protection claim until its own milestone passes.

## Repository/documentation policy

- `ROADMAP.md` is the single roadmap file.
- `README.md` is the public landing page, not a second roadmap.
- `SECURITY.md` contains security/disclosure guidance.
- `STABLE-RELEASE.md` documents the separately promoted stable channel.
- Historical engineering evidence remains recoverable from Git history and immutable checkpoint refs.
- Every future milestone/status change updates this file in the same development cycle.
