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
Beta11  COMPLETE / FROZEN
```

Current milestone:

```text
B12-2 — PowerShell & Script Abuse Expansion
```

Latest accepted engineering checkpoint:

```text
checkpoint/v012-beta12-b121-pass
cd8b3e89211afe29bf32a2646f4210c73179bc1f
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

**Status: COMPLETE / FROZEN**

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
- **B11-8 — Clean-PC Install / Upgrade / Uninstall Acceptance** — `checkpoint/v011-beta11-b118-pass` / `46d18b77aa382573e1e4e2a2eb381bcb71e03a69` — ACCEPTED / FROZEN.
- **B11-9 — Windows Release Candidate Acceptance & Freeze** — `checkpoint/v011-beta11-b119-pass` / `3c5204ca949d41d3a740b8745ab9af06913b8555` — ACCEPTED / FROZEN.

### Accepted Beta11 evidence summary

**B11-2** — Windows CI and local acceptance PASS on exact SHA `92b6317aa9e642a0062268bce9f92bb0a4ffb1a1`; reproducible manifest rules, complete inventory/hashing and packaged runtime probes accepted. PyInstaller byte identity across differing tool environments is not claimed.

**B11-3** — Windows CI run `35249033734` and local acceptance PASS on exact SHA `4ce33199bb72d87c09b0c204a40c2046efcb615a`; contract digest `f084b67d16b87e17722e70890be13ba33fcd10d7c3ece43b499fcb01020e5aa6`; exact ownership evidence required; unknown children and persistent data preserved by default.

**B11-4** — Windows CI run `35251500218` and local acceptance PASS on exact SHA `5ec361050f4c490652f88c30ad3a3b60e586fecb`; health-contract digest `1c079318ceac42c510216cf6bdb70d3067a21bf47c36ba21be47766fed0f6632`; diagnostics remain read-only.

**B11-5** — Windows CI run `35253271696` and local acceptance PASS on exact SHA `19e40b9b41f4d87b3f081bb7e8bfb5b155db4660`; persistent-data model digest `38df2751392cd71bec8662c6d4f80b287c30aeb70841606399057254fe7a2a08`; five persistent classes; uninstall preserves persistent data by default.

**B11-6** — Windows CI run `35255724334` and local acceptance PASS on exact SHA `25fc9b50b17d9deb65d61a8e8994334259bb5042`; `938 passed, 38 warnings`; upgrade-migration digest `d2aa15228ba6d7e84b8cef074f132718549373d51b35d93da6f12aac54c700d9`; migration mode `COPY_VERIFY_SWITCH_KEEP_SOURCE`; rollback mode `POINTER_ROLLBACK_KEEP_BOTH_DATASETS`.

**B11-7** — Windows CI run `35258890265` and local Windows acceptance PASS on exact SHA `c7ca5e86af196863cc980bcd1e8616447d9f3d8a`; CI `958 passed, 38 warnings`; release-provenance contract digest `a19d1ea8ad887b670cbbb9aef1a09db17e806fd59e5e89b603f9574c1912f109`; factual signing states are `UNSIGNED`, `SIGNED_UNVERIFIED`, `SIGNED_VERIFIED`; signing, verification, private-key use, certificate enrollment, timestamping, publication and artifact mutation remain unavailable.

Across accepted B11 milestones, canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2` and no general response-authority expansion has occurred.

### B11-8 accepted evidence

Windows CI run `35262528541` and local Windows acceptance both PASS on exact SHA `46d18b77aa382573e1e4e2a2eb381bcb71e03a69`.

- CI: `981 passed, 38 warnings in 117.42s`;
- local: `981 passed, 38 warnings in 98.02s`;
- lifecycle contract digest `8fb9060e3e41146a400a9cebdeec8978b96909c6aa6b2e29327ad9c60fb36269` matched CI and local;
- lifecycle transcript digest `1d010b2ff4a4e52f8fed405180ff404331c4ada08684cf1bc1e126600b62bf22` matched CI and local;
- execution remained exactly `EXPLICIT_DISPOSABLE_TEMP_WORKSPACE_ONLY`;
- install, upgrade and uninstall fixture lifecycle executed successfully;
- persistent data, unknown product children and the outside-workspace canary were preserved;
- unsafe scope was rejected;
- real machine-scope install/upgrade/uninstall, HKLM mutation, privilege elevation, service/driver/autostart registration remained unavailable;
- canonical coverage remained `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- no response-authority or protection-coverage expansion occurred.

### B11-9 accepted evidence — FINAL BETA11 FREEZE

Windows CI run `35336006673` and local Windows acceptance both PASS on exact SHA `3c5204ca949d41d3a740b8745ab9af06913b8555`.

- CI: `993 passed, 38 warnings`; local: `993 passed, 38 warnings`;
- freeze contract digest matched exactly: `abb472aef2a65878043a1340058baba251320e151c4321bc6093776215127608`;
- all nine accepted Beta11 predecessor checkpoints resolved to their immutable accepted SHAs;
- B11-8 lifecycle replay PASS with the accepted contract and transcript digests;
- live first-run health reported `READY`;
- fresh Windows onedir artifact built from the exact B11-9 acceptance commit;
- artifact manifest validation PASS;
- packaged `--identity-json`, `--self-check` and `--smoke` probes PASS;
- CI artifact SHA-256 `2cec222ae1366da5e852049216093897ad953f65493066d81438f2a56fbc8c6e`;
- local artifact SHA-256 `2ecc6e817f854c8c89c7c260103e15edae481eb2236f2944d1559ddd0ce4b324`;
- differing PyInstaller artifact bytes across environments are not treated as a failure because byte-for-byte cross-environment identity is not an accepted claim; each artifact is independently bound to and verified against the exact source commit;
- actual Windows Authenticode state was `UNSIGNED` in both accepted environments;
- unsigned engineering release-candidate acceptance is factual; signed public-release readiness is **not** claimed;
- B11-9 did not sign, publish, elevate, install into real machine scope, register services/drivers/autostart, mutate HKLM, add network/cloud requirements, expand response authority or promote protection coverage;
- final canonical coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- immutable final Beta11 checkpoint is `checkpoint/v011-beta11-b119-pass` at `3c5204ca949d41d3a740b8745ab9af06913b8555`.

**Beta11 is COMPLETE / FROZEN.**

## Beta12 — Active Protection & Detection Expansion

**Status: IN PROGRESS**

Goal: improve Sentinel as an antivirus before installer/public-release work by expanding evidence-backed Windows detection, correlation, verification and low-noise operation while preserving the accepted Beta11 authority and privacy boundaries.

Baseline inherited from Beta11:

```text
PARTIAL   4
GAP       0
VERIFIED  2
```

Verified baseline scenarios remain exactly:

```text
B7-POWERSHELL-001
B7-RANSOMWARE-001
```

### Beta12 freeze target

- at least **4 total VERIFIED scenarios**, therefore at least **2 newly earned VERIFIED scenarios**;
- every new VERIFIED promotion requires accepted Windows evidence; synthetic-only evidence cannot promote VERIFIED;
- positive controls and benign/negative controls are required for new detection claims;
- performance regressions must fail acceptance;
- canonical GAP remains zero;
- no broad-protection claim may exceed accepted evidence;
- no automatic quarantine, repair, restore, process termination, trust mutation or privileged/system mutation is added by the foundation;
- core acceptance remains local-first with no mandatory cloud or network dependency;
- installer, signing and public-release work are explicitly deferred until after Beta12.

### B12-0 accepted evidence

Windows CI run `35338604879` and local Windows acceptance both PASS on exact SHA `0015feb80c550b9c67707f24f4042a45412e7af3`.

- CI: `1006 passed, 38 warnings in 98.11s`;
- local: `1006 passed, 38 warnings in 82.88s`;
- contract digest matched exactly: `ce63f8841986fd9707e72011573b9907e251963854cc235ab3d3fb824b9fd857`;
- baseline remained `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- final Beta12 target requires at least `4` total VERIFIED scenarios and at least `2` newly earned VERIFIED scenarios;
- no coverage promotion, protection-claim expansion or response-authority expansion occurred;
- installer/signing/publication work remains deferred until after Beta12.

### B12-1 accepted evidence

Windows CI run `35349190717` and local Windows acceptance both PASS on exact SHA `cd8b3e89211afe29bf32a2646f4210c73179bc1f`.

- CI: `1042 passed, 38 warnings in 118.45s`;
- local: `1042 passed, 38 warnings in 90.65s`;
- contract digest matched exactly: `1ebfed393e8a63fe7bdc57bba634a1af7a04a1ffb341d049a603b1910ecd91d6`;
- process→file correlation binding PASS;
- optional parent→child ancestry binding PASS;
- missing ancestry remains explicitly unknown;
- raw paths, command lines and usernames remain uncollected;
- coverage remained `PARTIAL=4 / GAP=0 / VERIFIED=2`;
- no authority, network or cloud requirement expansion occurred.

### Planned Beta12 line

1. **B12-0 — Active Protection Foundation** — `checkpoint/v012-beta12-b120-pass` / `0015feb80c550b9c67707f24f4042a45412e7af3` — ACCEPTED / FROZEN.
2. **B12-1 — Process/File Correlation 2.0** — `checkpoint/v012-beta12-b121-pass` / `cd8b3e89211afe29bf32a2646f4210c73179bc1f` — ACCEPTED / FROZEN.
3. **B12-2 — PowerShell & Script Abuse Expansion** — 🚧 CURRENT — broaden harmless real-Windows script-abuse verification.
4. **B12-3 — Persistence & Autostart Detection** — evidence-backed startup/persistence detection with benign controls.
5. **B12-4 — Suspicious Process Tree Intelligence** — deterministic parent/child and suspicious-chain analysis.
6. **B12-5 — Ransomware Protection Expansion** — broaden safe ransomware-like evidence and reduce false positives.
7. **B12-6 — Local Reputation & Hash Intelligence** — local signer/hash/known-good context without mandatory cloud lookup.
8. **B12-7 — Low-Noise Tuning & Performance** — false-positive, latency and resource-budget gates.
9. **B12-8 — Verified Coverage Expansion & Product Integration** — reconcile earned verification into product evidence/UI.
10. **B12-9 — Windows Active Protection Acceptance & Freeze** — final exact CI + local acceptance and immutable checkpoint.

Current engineering branch:

```text
feature/v012-beta12-b122-powershell-script-abuse-expansion
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
