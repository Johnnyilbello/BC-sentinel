# BC Sentinel — Canonical Roadmap

This is the **only roadmap source of truth** for BC Sentinel. Accepted engineering checkpoints are immutable. Documentation may advance after an engineering freeze, but accepted checkpoints never move. Detailed historical evidence remains recoverable from Git history and immutable checkpoint refs.

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
B11-8 — Clean-PC Install / Upgrade / Uninstall Acceptance
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta11-b117-pass
c7ca5e86af196863cc980bcd1e8616447d9f3d8a
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

B11-8 introduces a second tightly bounded execution surface only for product-lifecycle acceptance: install/upgrade/uninstall fixture execution inside an explicitly confirmed disposable OS-temp workspace. It does **not** grant real machine-scope installation, HKLM mutation, Program Files/ProgramData mutation, privilege elevation, service/driver registration or autostart.

## Accepted foundations

### Beta5 — Technician / recovery hardening

**COMPLETE / FROZEN** — hardened recovery workflows, hostile-target assessment, evidence packaging, controlled real-PC acceptance and portable technician foundations.

### Beta6 — Technician UX and guided resolution

**COMPLETE / FROZEN**

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

### Beta7 — Detection Coverage & Incident Intelligence

**COMPLETE / FROZEN**

```text
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

### Beta8 — Verified Detection & Predictive Defense

**COMPLETE / FROZEN**

```text
checkpoint/v011-beta8-b87-pass
3c32157dd0c6bb852438319766a9345b0b9f5f1e
```

Beta8 intentionally remained `PARTIAL=6 / GAP=0 / VERIFIED=0` because detector evidence was synthetic/in-memory.

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

- Windows CI run `35230121430` PASS and local Windows PASS on exact SHA `89d2b0d59c73ad5d07d46af58db03d03c6fbfdc9`;
- `845 passed, 38 warnings` in both environments;
- all `6/6` Beta10 value pillars demonstrated by accepted evidence;
- final coverage `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- verified scenarios `B7-POWERSHELL-001` and `B7-RANSOMWARE-001`;
- reversible-response scope `DISPOSABLE_TEMP_WORKSPACE_ONLY`;
- general response execution disabled;
- no broad-protection claim, credential access, network I/O or cloud requirement.

## Beta11 — Windows Productization & Release Readiness

**Status: IN PROGRESS**

Goal: convert the accepted Beta10 source into a Windows product that can be built, installed, started, upgraded, rolled back and uninstalled predictably without weakening the accepted security, privacy or evidence boundaries.

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
- **B11-6 — Upgrade / Rollback + Config Migration** — `checkpoint/v011-beta11-b116-pass` / `25fc9b50b17d9deb65d61a8e8994334259bb5042` — ACCEPTED / FROZEN.
- **B11-7 — Release Provenance + Signing Readiness** — `checkpoint/v011-beta11-b117-pass` / `c7ca5e86af196863cc980bcd1e8616447d9f3d8a` — ACCEPTED / FROZEN.

### Accepted Beta11 evidence summary

**B11-2** — Windows CI and local acceptance PASS on exact SHA `92b6317aa9e642a0062268bce9f92bb0a4ffb1a1`; reproducible manifest rules, complete inventory/hashing and packaged runtime probes accepted. PyInstaller byte identity across differing tool environments is not claimed.

**B11-3** — Windows CI run `35249033734` and local acceptance PASS on exact SHA `4ce33199bb72d87c09b0c204a40c2046efcb615a`; contract digest `f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6`; exact ownership evidence required; unknown children and persistent data preserved by default.

**B11-4** — Windows CI run `35251500218` and local acceptance PASS on exact SHA `5ec361050f4c490652f88c30ad3a3b60e586fecb`; health-contract digest `1c079318ceac42c510216cf6bdb70d3067a21bf47c36ba21be47766fed0f6632`; diagnostics remain read-only.

**B11-5** — Windows CI run `35253271696` and local acceptance PASS on exact SHA `19e40b9b41f4d87b3f081bb7e8bfb5b155db4660`; persistent-data model digest `38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08`; five persistent classes; uninstall preserves persistent data by default.

**B11-6** — Windows CI run `35255724334` and local acceptance PASS on exact SHA `25fc9b50b17d9deb65d61a8e8994334259bb5042`; `938 passed, 38 warnings`; upgrade-migration digest `d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9`; migration mode `COPY_VERIFY_SWITCH_KEEP_SOURCE`; rollback mode `POINTER_ROLLBACK_KEEP_BOTH_DATASETS`.

**B11-7** — Windows CI run `35258890265` and local Windows acceptance PASS on exact SHA `c7ca5e86af196863cc980bcd1e8616447d9f3d8a`; CI `958 passed, 38 warnings`; release-provenance contract digest `a19d1ea8ad887b670cbbb9aef1a09db17e806fd59e5e89b603f9574c1912f109`; factual signing states are `UNSIGNED`, `SIGNED_UNVERIFIED`, `SIGNED_VERIFIED`; signing, verification, private-key use, certificate enrollment, timestamping, publication and artifact mutation remain unavailable.

Across accepted B11 milestones, canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2` and no general response-authority expansion has occurred.

### B11-8 — Clean-PC Install / Upgrade / Uninstall Acceptance 🚧 CURRENT

Execute and verify the accepted install-lifecycle semantics on Windows using a real filesystem lifecycle inside an explicitly confirmed disposable OS-temp workspace. B11-8 is execution evidence for bounded product-owned lifecycle behavior; it is not permission to install into the operator's real machine scope.

Acceptance requirements:

- exact accepted predecessor is `checkpoint/v011-beta11-b117-pass` / `c7ca5e86af196863cc980bcd1e8616447d9f3d8a`;
- accepted B11-7 source paths remain immutable except canonical roadmap documentation;
- exact accepted bindings remain B11-3 contract `f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6`, B11-5 model `38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08`, B11-6 contract `d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9` and B11-7 provenance contract `a19d1ea8ad887b670cbbb9aef1a09db17e806fd59e5e89b603f9574c1912f109`;
- execution scope is exactly `EXPLICIT_DISPOSABLE_TEMP_WORKSPACE_ONLY`;
- initialization requires explicit confirmation, a clean OS-temp workspace, the B11-8 workspace-name prefix and an exact lifecycle marker;
- clean install creates only fixture representations of the product payload, Start Menu shortcut and uninstall metadata under the disposable workspace; no real `Program Files`, `ProgramData`, Start Menu or HKLM mutation occurs;
- exact ownership manifest and per-file SHA-256 verification are required before destructive lifecycle actions;
- runtime-created persistent configuration, logs, quarantine metadata, quarantine payload and lifecycle metadata are distinct from installer-owned files;
- upgrade stages the target payload, verifies staged hashes before activation, preserves the persistent-data tree and keeps the previous application payload;
- uninstall removes only hash-verified manifested product files, preserves unknown children and preserves persistent data by default;
- missing/tampered ownership evidence, marker mismatch, path escape or non-disposable scope fails closed before destructive action;
- an outside-workspace canary must remain unchanged across the full lifecycle;
- real machine-scope install/upgrade/uninstall, HKLM mutation, privilege elevation, service/driver/autostart registration, Defender/firewall changes, automatic update, signing and release publication remain unavailable;
- no network/cloud requirement, response-authority expansion or protection-coverage promotion;
- canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- full Beta5→Beta11 regression must pass on Windows;
- exact Windows CI + local acceptance on the same SHA are required before `checkpoint/v011-beta11-b118-pass` may be created.

### Remaining planned Beta11 line

- **B11-9 — Windows Release Candidate Acceptance & Freeze** — full regression, final productization evidence reconciliation and immutable release-candidate freeze.

Current engineering branch:

```text
feature/v011-beta11-b118-clean-pc-lifecycle-acceptance
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
