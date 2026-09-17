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
B11-6 — Upgrade / Rollback + Config Migration
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta11-b115-pass
19e40b9b41f4d87b3f081bb7e8bfb5b155db4660
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

### Accepted Beta11 line

- **B11-0 — Windows Productization Foundation** — `checkpoint/v011-beta11-b110-pass` / `0bee65100c6713d11dedd56c28ee3118f0082624` — ACCEPTED / FROZEN.
- **B11-1 — Canonical Desktop Entry + Runtime Identity** — `checkpoint/v011-beta11-b111-pass` / `2d49bc2037d3d1f3fb40280277cf8d53927cc68b` — ACCEPTED / FROZEN.
- **B11-2 — Reproducible Windows Onedir Build** — `checkpoint/v011-beta11-b112-pass` / `92b6317aa9e642a0062268bce9f92bb0a4ffb1a1` — ACCEPTED / FROZEN.
- **B11-3 — Installer / Uninstaller Contract** — `checkpoint/v011-beta11-b113-pass` / `4ce33199bb72d87c09b0c204a40c2046efcb615a` — ACCEPTED / FROZEN.
- **B11-4 — First-Run Health + Repair Guidance** — `checkpoint/v011-beta11-b114-pass` / `5ec361050f4c490652f88c30ad3a3b60e586fecb` — ACCEPTED / FROZEN.
- **B11-5 — Persistent App Data + Logs + Quarantine Model** — `checkpoint/v011-beta11-b115-pass` / `19e40b9b41f4d87b3f081bb7e8bfb5b155db4660` — ACCEPTED / FROZEN.

### B11-2 accepted evidence

Windows CI run `35244670724` and local Windows acceptance both PASS on exact SHA `92b6317aa9e642a0062268bce9f92bb0a4ffb1a1`.

CI evidence:

- `876 passed, 38 warnings in 123.57s`;
- Python `3.12.10`, PyInstaller `6.22.3`;
- onedir artifact `BC-Sentinel-Beta11.exe` produced and integrity-validated;
- `217` files / `132916675` bytes;
- artifact SHA-256 `b072e918505c9590a4ac5ba95282c3a3a992b8f7a990371416d2ba0f35552cfa`;
- tree digest `2b82e97e749e482c50d50dcddce48b822292cb4134f40d3bc9c45ad7a7fd7e69`;
- packaged `--identity-json`, `--self-check` and `--smoke` probes PASS.

Local Windows evidence:

- `876 passed, 38 warnings in 99.39s`;
- Python `3.12.10`, PyInstaller `6.22.2`;
- onedir artifact produced and integrity-validated;
- `215` files / `124433579` bytes;
- artifact SHA-256 `d85afc0850db24470b90d10495b28193b8c873fb4ef847b9488d9601653c70d1`;
- tree digest `f58f87ca200511b429397277ea520fe80937cf3ef38ea90bc371458aa5078a39`;
- packaged `--identity-json`, `--self-check` and `--smoke` probes PASS.

B11-2 reproducibility means immutable source binding, deterministic manifest rules, complete artifact inventory/hashing and runtime acceptance. It does **not** claim byte-identical PyInstaller output across different dependency/tool versions or Windows build environments.

### B11-3 accepted evidence

Windows CI run `35249033734` and local Windows acceptance both PASS on exact SHA `4ce33199bb72d87c09b0c204a40c2046efcb615a`.

- CI: `893 passed, 38 warnings in 118.07s`;
- local: `893 passed, 38 warnings in 172.84s`;
- deterministic contract digest `f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6` matched CI and local;
- accepted B11-2 predecessor immutability and repository hygiene PASS;
- lifecycle operation count `4`: INSTALL, REPAIR, UPGRADE, UNINSTALL;
- planned product-owned resource count `4`;
- ownership manifest required before removal;
- unknown children preserved and persistent app data preserved by default;
- elevation policy `ON_DEMAND_MACHINE_SCOPE_ONLY`;
- installer/uninstaller execution remains unavailable at this milestone;
- service/driver installation and autostart registration remain unavailable;
- artifact signing remains false;
- no coverage promotion and no response-authority expansion;
- canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`.

### B11-4 accepted evidence

Windows CI run `35251500218` and local Windows acceptance both PASS on exact SHA `5ec361050f4c490652f88c30ad3a3b60e586fecb`.

- CI: `905 passed, 38 warnings in 121.53s`;
- local: `905 passed, 38 warnings in 90.25s`;
- deterministic health-contract digest `1c079318ceac42c510216cf6bdb70d3067a21bf47c36ba21be47766fed0f6632` matched CI and local;
- live first-run health status `READY` in CI and local acceptance;
- `10` critical checks and `6` optional checks modeled;
- local acceptance reported `critical_failure_count=0`, `warning_count=0` and `ready_to_start=true`;
- Windows/x64/Python 3.12, canonical runtime identity and Trust Center core all validated;
- required runtime modules and accepted feature dependencies were available in the local probe;
- health diagnostics remain read-only and non-mutating;
- repair execution, package installation, privilege elevation, service/driver/autostart registration, Defender/firewall changes, automatic update execution, network and cloud requirements remain unavailable;
- no coverage promotion and no response-authority expansion;
- canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`.

### B11-5 accepted evidence

Windows CI run `35253271696` and local Windows acceptance both PASS on exact SHA `19e40b9b41f4d87b3f081bb7e8bfb5b155db4660`.

- CI: `920 passed, 38 warnings in 119.99s`;
- local: `920 passed, 38 warnings in 102.01s`;
- deterministic persistent-data model digest `38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08` matched CI and local;
- canonical machine-data root is `{PROGRAM_DATA}\BC Sentinel`;
- `5` distinct persistent data classes are modeled: configuration/state, logs, quarantine metadata, quarantine payloads and lifecycle metadata;
- quarantine metadata and untrusted payloads remain separated;
- legacy B6 storage remains `{LOCAL_APP_DATA}\BCSentinel\B656` and automatic migration is not performed by B11-5;
- uninstall preserves persistent data by default;
- exact ownership evidence is required and unknown children fail closed for destructive lifecycle decisions;
- destructive execution, permission enforcement, migration execution and installer/uninstaller execution remain unavailable;
- no network/cloud requirement, coverage promotion or response-authority expansion;
- canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`.

### B11-6 — Upgrade / Rollback + Config Migration 🚧 CURRENT

Define deterministic upgrade, rollback and configuration-migration rules over the accepted B11-5 persistent-data model without mutating a real host. B11-6 is a planning and integrity milestone; clean-PC lifecycle execution remains reserved for later acceptance.

Acceptance requirements:

- exact accepted predecessor is `checkpoint/v011-beta11-b115-pass` / `19e40b9b41f4d87b3f081bb7e8bfb5b155db4660`;
- accepted B11-5 source paths remain immutable except canonical roadmap documentation;
- the B11-6 contract binds to the exact accepted B11-5 persistent-data model digest;
- legacy B6 quarantine payloads and rollback snapshots remain typed as `QUARANTINE_PAYLOADS`; journal and restart-safe recovery records remain `QUARANTINE_METADATA`;
- legacy migration mode is `COPY_VERIFY_SWITCH_KEEP_SOURCE`: source data is preserved and never silently moved/deleted;
- every migrated file requires integrity evidence and destination hashes must match source hashes before a future activation;
- unknown source children, unmanifested destination entries, path escapes and symlink/reparse escapes fail closed;
- config migration accepts only a known schema with a valid source digest, is deterministic/idempotent and preserves the source payload on failure;
- rollback requires previous dataset identity + manifest digest, preserves both current and legacy datasets, and never implies quarantine restore;
- host migration, host upgrade, host rollback, config writes, legacy-source deletion, installer/uninstaller execution and privilege elevation remain unavailable in B11-6;
- no network/cloud requirement, service/driver/autostart registration or protection-coverage promotion;
- canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- full Beta5→Beta11 regression must pass on Windows;
- exact Windows CI + local acceptance on the same SHA are required before `checkpoint/v011-beta11-b116-pass` may be created.

### Remaining planned Beta11 line

- **B11-7 — Release Provenance + Signing Readiness** — artifact provenance, factual signing state, hashes and release evidence; signing is never implied when absent.
- **B11-8 — Clean-PC Install / Upgrade / Uninstall Acceptance** — real Windows lifecycle acceptance on clean/disposable systems.
- **B11-9 — Windows Release Candidate Acceptance & Freeze** — full regression and immutable release-candidate freeze.

Current engineering branch:

```text
feature/v011-beta11-b116-upgrade-rollback-config-migration
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
