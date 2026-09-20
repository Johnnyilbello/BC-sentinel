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
Beta12  COMPLETE / FROZEN
Beta13  COMPLETE / FROZEN
Beta14  IN PROGRESS
```

Current milestone:

```text
B14-0 — Verified Protection & Independent-Test Readiness Foundation
```

Latest accepted engineering checkpoint:

```text
checkpoint/v013-b137-pass
01df0a9c58b856cfe841909fb5c39f7ef71decb8
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
VERIFIED  7
```

Verified scenarios:

```text
B7-POWERSHELL-001
B7-RANSOMWARE-001
B12-SCRIPT-ABUSE-001
B12-AUTOSTART-LINK-001
B12-PROCESS-TREE-001
B12-RANSOMWARE-PROCESS-001
B12-LOCAL-REPUTATION-001
```

`VERIFIED` remains scenario-specific. Every Beta12 promotion is bounded to its accepted Windows evidence and limitation; the current state does not claim broad protection against all scripts, persistence methods, ransomware families, process trees or unknown files.

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

**Status: COMPLETE / FROZEN**

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

### B12-2 accepted evidence

Windows CI run `35350665000` and local Windows acceptance both PASS on exact SHA `dedf78ae920b87f44636a0b9bd0c9708d2ae760b`.

- CI: `1065 passed, 38 warnings in 66.70s`;
- local: `1065 passed, 38 warnings in 85.87s`;
- contract digest matched exactly: `c2e02eebf4ef9f7dadc0bdd60d306c38d02e8fc97b126e672fcccd80417b3e07`;
- positive live script-mutation control: `DETECTED`;
- administrative control: `REVIEW_REQUIRED`;
- benign control: `NO_MATCH`;
- new scenario `B12-SCRIPT-ABUSE-001` earned `VERIFIED`;
- coverage advanced to `PARTIAL=4 / GAP=0 / VERIFIED=3`;
- detector→Security Graph→incident binding PASS;
- no command line, script content or raw path was exported;
- no authority, network or cloud requirement expansion occurred.

### B12-3 accepted evidence

Windows CI run `35354447114` and local Windows acceptance both PASS on exact SHA `90776f9b0e3f1a9c034b79a5886b30df0db41e5c`.

- CI: `1089 passed, 38 warnings in 125.90s`;
- local: `1089 passed, 38 warnings in 102.01s`;
- contract digest matched exactly: `f5328e918e767e8e170cd794d695db52ba388b35bfbfb49aa5a1cc9b58a647b6`;
- positive autostart-like shortcut: `DETECTED`;
- administrative shortcut: `REVIEW_REQUIRED`;
- benign shortcut: `NO_MATCH`;
- new scenario `B12-AUTOSTART-LINK-001` earned `VERIFIED`;
- coverage advanced to `PARTIAL=4 / GAP=0 / VERIFIED=4`;
- Beta12 minimum VERIFIED target is now met;
- `B7-PERSISTENCE-001` remains correctly `PARTIAL`;
- no real Startup folder, Registry Run key, Scheduled Task or service mutation occurred;
- no authority, network or cloud requirement expansion occurred.

### B12-4 accepted evidence

Windows CI run `35356083040` and local Windows acceptance both PASS on exact SHA `8e1cb119ef225efbf89471bddc645dc5416c8e01`.

- CI: `1113 passed, 38 warnings in 128.26s`;
- local: `1113 passed, 38 warnings in 97.13s`;
- contract digest matched exactly: `52cd72997ecc33293e50d447d15feca83ebc397d0b122a2bb5ca7bc71907b2f6`;
- positive process chain: `DETECTED`;
- administrative process chain: `REVIEW_REQUIRED`;
- benign process chain: `NO_MATCH`;
- new scenario `B12-PROCESS-TREE-001` earned `VERIFIED`;
- coverage advanced to `PARTIAL=4 / GAP=0 / VERIFIED=5`;
- no command line or raw path export and no response-authority expansion occurred.

### B12-5 accepted evidence

Windows CI run `35357431834` and local Windows acceptance both PASS on exact SHA `04dfef15f5cb5583fd49b878efc9de663e74cdcb`.

- CI: `1133 passed, 38 warnings in 123.92s`;
- local: `1133 passed, 38 warnings in 88.37s`;
- contract digest matched exactly: `9e4398b3a8049537636b6f21579a24425ab0ad3673ff780064e3677fd6164550`;
- accepted B9 live controls retained outcomes `DETECTED / REVIEW_REQUIRED / NO_MATCH`;
- exact live harness process attribution bound successfully into the Security Graph and incident;
- new scenario `B12-RANSOMWARE-PROCESS-001` earned `VERIFIED`;
- coverage advanced to `PARTIAL=4 / GAP=0 / VERIFIED=6`;
- no new file-mutation harness, no broad ransomware claim, and no authority/network/cloud expansion occurred.

### B12-6 accepted evidence

Windows CI run `35377927800` and local Windows acceptance both PASS on exact SHA `b1f55ea32564d72cae6056308f90f8b41137dc94`.

- CI: `1158 passed, 38 warnings in 121.26s`;
- local: `1158 passed, 38 warnings in 90.61s`;
- contract digest matched exactly: `7a16fbc6a4deef6d4a8f5a71a7b55e260dd98091eac2b0d5c19643ed2efd51f7`;
- known-good signed + local allowlist: `TRUSTED_LOCAL`;
- signed unknown: `UNKNOWN_SIGNED`;
- unsigned unknown: `UNKNOWN_UNSIGNED`;
- new scenario `B12-LOCAL-REPUTATION-001` earned `VERIFIED`;
- coverage advanced to `PARTIAL=4 / GAP=0 / VERIFIED=7`;
- no maliciousness verdict for unknown files, no trust mutation, no file execution, and no network/cloud authority expansion.

### B12-7 accepted evidence

Windows CI run `35379621078` and local Windows acceptance both PASS on exact SHA `8e5614c919611a7b072dd0a4f462c56751ba331d`.

- CI: `1176 passed, 38 warnings in 123.47s`;
- local: `1176 passed, 38 warnings in 95.26s`;
- contract digest matched exactly: `81d9c55313fcd3720e40c53980150f6684844d35cf61e5e1794a8b7fbfc2c8c9`;
- 20 measured low-noise iterations passed in both accepted environments;
- local p95 wall: `1.2708 ms`; local p95 CPU: `0.0 ms`; local max RSS delta: `0.0625 MiB`;
- false-positive detections: `0`; outcome drift: `0`; user interruptions: `0`;
- coverage remained correctly `PARTIAL=4 / GAP=0 / VERIFIED=7`;
- B12-7 earned no new VERIFIED scenario and made no detector-threshold, authority, network or cloud expansion.

### B12-8 accepted evidence

Windows CI run `35380765055` and local Windows acceptance both PASS on exact SHA `88a7f3df43ba329cb632252ef03928b069cbcc3d`.

- CI: `1201 passed, 39 warnings in 130.30s`;
- local: `1201 passed, 39 warnings in 90.10s`;
- product integration contract digest matched exactly: `2e3029c2d222ad13488d5cbf10e9224eff8b1b8100fc2062ac1ba8009bf2618d`;
- product evidence digest matched exactly: `91d812eb9bd41cd00402c39f03c61e61a11081ba46e21d993bff258b92f60fa0`;
- coverage remained `PARTIAL=4 / GAP=0 / VERIFIED=7`;
- Trust Center rendered 11 scenarios and 7 Beta12 capabilities;
- Trust Center exposed 0 action buttons and 0 horizontal overflow at 560/680/960/1440 px;
- local B12-7 replay: p95 wall `1.2099 ms`, p95 CPU `0.0 ms`, max RSS delta `0.046875 MiB`, false positives `0`, outcome drift `0`, user interruptions `0`;
- B12-8 earned no new VERIFIED scenario and did not expand response authority, trust mutation, network or cloud requirements.

### Planned Beta12 line

1. **B12-0 — Active Protection Foundation** — `checkpoint/v012-beta12-b120-pass` / `0015feb80c550b9c67707f24f4042a45412e7af3` — ACCEPTED / FROZEN.
2. **B12-1 — Process/File Correlation 2.0** — `checkpoint/v012-beta12-b121-pass` / `cd8b3e89211afe29bf32a2646f4210c73179bc1f` — ACCEPTED / FROZEN.
3. **B12-2 — PowerShell & Script Abuse Expansion** — `checkpoint/v012-beta12-b122-pass` / `dedf78ae920b87f44636a0b9bd0c9708d2ae760b` — ACCEPTED / FROZEN.
4. **B12-3 — Persistence & Autostart Detection** — `checkpoint/v012-beta12-b123-pass` / `90776f9b0e3f1a9c034b79a5886b30df0db41e5c` — ACCEPTED / FROZEN.
5. **B12-4 — Suspicious Process Tree Intelligence** — `checkpoint/v012-beta12-b124-pass` / `8e1cb119ef225efbf89471bddc645dc5416c8e01` — ACCEPTED / FROZEN.
6. **B12-5 — Ransomware Protection Expansion** — `checkpoint/v012-beta12-b125-pass` / `04dfef15f5cb5583fd49b878efc9de663e74cdcb` — ACCEPTED / FROZEN.
7. **B12-6 — Local Reputation & Hash Intelligence** — `checkpoint/v012-beta12-b126-pass` / `b1f55ea32564d72cae6056308f90f8b41137dc94` — ACCEPTED / FROZEN.
8. **B12-7 — Low-Noise Tuning & Performance** — `checkpoint/v012-beta12-b127-pass` / `8e5614c919611a7b072dd0a4f462c56751ba331d` — ACCEPTED / FROZEN.
9. **B12-8 — Verified Coverage Expansion & Product Integration** — `checkpoint/v012-beta12-b128-pass` / `88a7f3df43ba329cb632252ef03928b069cbcc3d` — ACCEPTED / FROZEN.
10. **B12-9 — Windows Active Protection Acceptance & Freeze** — `checkpoint/v012-beta12-b129-pass` / `c8e51a2a3fc34c593905896d3b055f9fec252c4b` — ACCEPTED / FROZEN.

### B12-9 accepted evidence — FINAL BETA12 FREEZE

Windows CI run `35408596757` and local Windows acceptance both PASS on exact SHA `c8e51a2a3fc34c593905896d3b055f9fec252c4b`.

- CI: `1217 passed, 39 warnings in 127.11s`;
- local: `1217 passed, 39 warnings in 70.10s`;
- final freeze contract digest matched exactly: `1128d7d0e10bd086d92da2ef58697e665c4d1747b546f9ce6eafe9dd4771f2d2`;
- product evidence digest matched exactly: `91d812eb9bd41cd00402c39f03c61e61a11081ba46e21d993bff258b92f60fa0`;
- freeze evidence digest matched exactly: `19c2d31b9c4494d6c14b201b437d7afdb44dde0a474a5f0a79b1e5d1b2244839`;
- all nine predecessor Beta12 checkpoints resolved to their immutable accepted SHAs;
- final coverage is `PARTIAL=4 / GAP=0 / VERIFIED=7`;
- local fresh low-noise replay: p95 wall `1.0674 ms`, p95 CPU `0.0 ms`, max RSS delta `0.046875 MiB`, false positives `0`, outcome drift `0`, user interruptions `0`;
- Trust Center remained read-only with 11 scenarios, 7 capabilities, 0 action buttons and 0 horizontal overflow at 560/680/960/1440 px;
- B12-9 did not install, sign or publish artifacts and did not expand coverage, authority, network or cloud requirements.

**Beta12 is COMPLETE / FROZEN.**

## Beta13 — Consumer Product Readiness & Windows Distribution

**Status: COMPLETE / FROZEN**

Goal: turn the frozen Beta12 source into a consumer-ready Windows security product that can be trusted, installed, updated, supported and monetized without weakening the accepted Beta12 detection, privacy, low-noise or authority boundaries.

### B13-0 accepted evidence

Windows CI run `35409542186` and local Windows acceptance both PASS on exact SHA `6c1a3dedd48d2b26b716c199f74ea45d827ee01a`.

- CI: `1229 passed, 39 warnings in 126.63s`;
- local: `1229 passed, 39 warnings in 70.82s`;
- contract digest matched exactly: `f48eb06dc9a9e3e8936eeae5314b0c89b26ba730fe79202405e5ecc74a3d1f75`;
- readiness baseline: `READY=3 / PARTIAL=2 / BLOCKED=5`;
- seven public-release blockers were made explicit: safe response, background alerts, secure updates, installer lifecycle, code signing, licensing/trial and privacy/support;
- installer work is allowed, but installer alone is explicitly not public-launch readiness;
- Beta12 coverage and authority remained unchanged.

### B13-1 accepted evidence

Windows CI run `35410136549` and local Windows acceptance both PASS on exact SHA `cfb94fb65f90327504296809270bf3c573f083d0`.

- CI: `1240 passed, 40 warnings in 118.43s`;
- local: `1240 passed, 40 warnings in 111.21s`;
- contract digest matched exactly: `9baa16a968d8bc40cd2941074c2dfde490bcbf115e11d8686f500ea255e8f76c`;
- safe threat response moved to READY with Ask First, explicit-confirmation reversible quarantine and explicit-confirmation restore;
- background alerts moved to READY with local notification center, unread state, deduplication and tray adapter;
- response center UI: 8 pages, 3 acceptance alert cards, 0 horizontal overflow at 560/680/960/1440 px;
- automatic quarantine, automatic repair, process termination and destructive UI action remained disabled;
- readiness advanced to `READY=5 / PARTIAL=1 / BLOCKED=4` with five release blockers remaining.

### B13-2 accepted evidence

Windows CI run `35435345832` and local Windows acceptance both PASS on exact SHA `3e64155858d9b8c7efebc28aecc9689795159ae9`.

- CI: `1258 passed, 40 warnings in 118.05s`;
- local: `1258 passed, 40 warnings in 80.93s`;
- contract digest matched exactly: `b130fbd21e0031fad33e0e73d1b8685f189fc29cebab13a93b0c351e3cea82ff`;
- Ed25519-signed application manifest verified and payload staged without execution;
- tampered payload, expired manifest, replayed sequence and wrong pinned root were all rejected;
- signed rule bundle staged with two rules and enforced `DETECT_ONLY` disposition;
- rollback remained bounded to the previous verified state and non-executing in B13-2;
- no private update key was persisted or embedded;
- readiness advanced to `READY=6 / PARTIAL=1 / BLOCKED=3` with four release blockers remaining.

### B13-3 accepted evidence

Windows CI run `35437329011` and local Windows acceptance both PASS on exact SHA `b6014ef74ffc77814f489532c8f2d09fb92fe17f`.

- full regression: `1269 passed, 40 warnings` in both accepted environments;
- local regression time: `98.81s`;
- contract digest: `fc1f0f00b36331121b9dcf9487086781744e01907811f297c6732913ee2c6d0d`;
- real per-user NSIS installer compiled and executed without administrator requirement;
- packaged self-check and packaged UI smoke both PASS after real installation;
- real uninstall PASS;
- unknown install child and external persistent data preserved;
- local installer SHA-256: `f683f27665cef095d5034fac9367e2b2ed4b3ab23c1029faaf8d41282c432b42`;
- local payload tree digest: `be8640e513731cb03bef84b4782bd0094578f22314c2b945b1b972d9f8d008fb`;
- local installer evidence digest: `15d233c24de14acd77952adb5a3dd009c6f1bbefc93f7b284b123a65d2646f3e`;
- service, driver and autostart registration remained disabled;
- readiness advanced to `READY=7 / PARTIAL=1 / BLOCKED=2`; remaining release blockers: code signing, licensing/trial and privacy/support.

### B13-4 accepted evidence

Windows CI run `35444523093` and local Windows acceptance both PASS on exact SHA `c2dc1b0df4becc18afa56915bb47b29b533a9a55`.

- CI: `1283 passed, 40 warnings in 92.30s`;
- local: `1283 passed, 40 warnings in 87.04s`;
- pinned Microsoft package: `Microsoft.Windows.SDK.BuildTools 10.0.28000.2705`;
- verified package SHA-256: `8bfdfb6ca2633f531cf80b5fa22512ba61a394d7988f0970db83baadc67929ed`;
- SignTool bootstrap and cache validation PASS without requiring a manually configured Windows SDK;
- application, installer and uninstaller all received Authenticode SHA-256 signatures with RFC3161 timestamps;
- signer thumbprint consistency and post-sign artifact integrity PASS;
- real per-user install, packaged self-check, packaged UI smoke and uninstall all PASS;
- engineering/self-signed trust is explicitly not Public Trust; `CODE_SIGNING` remains a public-release blocker until a real trusted publisher certificate is used;
- SmartScreen reputation is not guaranteed and was not claimed;
- readiness remains `READY=7 / PARTIAL=1 / BLOCKED=2`; release blockers remain code signing, licensing/trial and privacy/support;
- canonical detection coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=7` with no response-authority expansion.

### B13-5 accepted evidence

Windows CI run `35446297278` and local Windows acceptance both PASS on exact SHA `cbead4c4e01818f5764ebeb82f85eb69f64e1f67`.

- CI: `1297 passed, 40 warnings in 128.18s`;
- local: `1297 passed, 40 warnings in 80.60s`;
- CI environment classified as `DISPOSABLE_WINDOWS_CI_RUNNER` with authoritative clean-PC evidence;
- local environment classified as `LOCAL_GUARDED_REHEARSAL` and correctly did not claim clean-PC authority;
- real B13-3 predecessor install PASS;
- real upgrade to the B13-4 engineering-signed target PASS;
- packaged self-check and UI smoke PASS both before and after upgrade;
- unknown user-owned install child and external persistent data preserved across upgrade and uninstall;
- uninstall removed product-owned executable, manifest, registry and Start Menu metadata;
- no administrator requirement, service, driver or autostart registration observed;
- CI lifecycle evidence digest: `7f94aaaf996944d05fa0d0e49a65f65eb3a0d9628511bcb7e8735259babb7cf8`;
- local lifecycle evidence digest: `b197747d44b5268b6713fd15873c6a62121d0aed851179007f2cf9b3003be3b9`;
- engineering signing remains non-Public-Trust and SmartScreen reputation remains unclaimed;
- canonical detection coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=7` with no authority expansion.

### B13-6 accepted evidence

Windows CI run `35447930415` and local Windows acceptance both PASS on exact SHA `b981afa453e6540e18e5ec1fac7da74ce9344829`.

- CI: `1311 passed, 41 warnings in 128.24s`;
- local: `1311 passed, 41 warnings in 82.00s`;
- commercial-readiness contract digest matched exactly: `5b4a2d43aff8c4e085d615cf9d285c3cdcbf35c4e0954d10a0557a1b71f2ff1f`;
- trial lifecycle PASS with 14-day local trial state;
- locally verified Ed25519 entitlement verifier PASS without embedding a private activation key;
- expired trial, invalid entitlement and unavailable activation all preserve accepted core protection;
- privacy, EULA and support surfaces PASS;
- explicit support-diagnostics export PASS with raw paths, command lines, usernames, license token/ID and file contents excluded;
- packaged consumer UI PASS with 9 pages and zero horizontal overflow at 560/680/960/1440 px;
- readiness advanced to `READY=9 / PARTIAL=0 / BLOCKED=1`;
- the sole remaining public-release blocker is `CODE_SIGNING`: engineering/self-signed Authenticode is not Public Trust and SmartScreen reputation remains unclaimed;
- canonical detection coverage remains `PARTIAL=4 / GAP=0 / VERIFIED=7` with no authority, network or cloud expansion.

### Planned Beta13 line

1. **B13-0 — Consumer Product Readiness Foundation** — `checkpoint/v013-b130-pass` / `6c1a3dedd48d2b26b716c199f74ea45d827ee01a` — ACCEPTED / FROZEN.
2. **B13-1 — Safe Threat Response & Notification UX** — `checkpoint/v013-b131-pass` / `cfb94fb65f90327504296809270bf3c573f083d0` — ACCEPTED / FROZEN.
3. **B13-2 — Secure Update Channel & Rule Delivery** — `checkpoint/v013-b132-pass` / `3e64155858d9b8c7efebc28aecc9689795159ae9` — ACCEPTED / FROZEN.
4. **B13-3 — Real Windows Installer Foundation** — `checkpoint/v013-b133-pass` / `b6014ef74ffc77814f489532c8f2d09fb92fe17f` — ACCEPTED / FROZEN.
5. **B13-4 — Code Signing & SmartScreen Readiness** — `checkpoint/v013-b134-pass` / `c2dc1b0df4becc18afa56915bb47b29b533a9a55` — ACCEPTED / FROZEN.
6. **B13-5 — Clean-PC Install / Upgrade / Uninstall Acceptance** — `checkpoint/v013-b135-pass` / `cbead4c4e01818f5764ebeb82f85eb69f64e1f67` — ACCEPTED / FROZEN.
7. **B13-6 — Trial / Licensing / Privacy / Support Readiness** — `checkpoint/v013-b136-pass` / `b981afa453e6540e18e5ec1fac7da74ce9344829` — ACCEPTED / FROZEN.
8. **B13-7 — Distribution Package & Release Candidate Freeze** — `checkpoint/v013-b137-pass` / `01df0a9c58b856cfe841909fb5c39f7ef71decb8` — ACCEPTED / FROZEN.

### B13-7 accepted evidence — FINAL BETA13 ENGINEERING RC FREEZE

Windows CI run `35450484582` and local Windows acceptance both PASS on exact SHA `01df0a9c58b856cfe841909fb5c39f7ef71decb8`.

- CI: `1326 passed, 41 warnings in 146.08s`; local: `1326 passed, 41 warnings in 91.38s`;
- all seven accepted Beta13 predecessor checkpoints resolved to their immutable SHAs;
- engineering release candidate build, distribution manifest, SHA-256 inventory and provenance validation PASS;
- real per-user install, packaged self-check, UI smoke, privacy-safe diagnostics export and uninstall PASS;
- CI clean-PC authority: `DISPOSABLE_WINDOWS_CI_RUNNER / authoritative=True`;
- local environment correctly remained `LOCAL_GUARDED_REHEARSAL / authoritative=False`;
- CI freeze evidence digest: `546143cabf89fba2a85cf00d418906513e346a55185e7485b18264b107bcba48`;
- local freeze evidence digest: `fdc370bae7c468f6c0a29f76b440fec4709bd6df244b831b5f45486796f30b3e`;
- service, driver and autostart remained disabled and canonical coverage remained `PARTIAL=4 / GAP=0 / VERIFIED=7`;
- engineering RC is READY; public/paid release remains blocked only by `CODE_SIGNING` because the accepted engineering certificate is not Public Trust;
- SmartScreen reputation remains explicitly unclaimed.

**Beta13 is COMPLETE / FROZEN.**

## Beta14 — Verified Protection Expansion & Independent-Test Readiness

**Status: IN PROGRESS**

Goal: move from a productized engineering RC to broader evidence-backed protection quality. Beta14 measures the gaps that matter for independent antivirus evaluation without inflating claims: real-world protection evidence, prevalent-malware coverage, false positives, system-level performance, behavioral detection breadth, offline/online behavior and repeatable evidence.

B14 does **not** make BC Sentinel independently certified and does not promote any detection scenario without accepted Windows evidence. Ordinary CI/local acceptance remains harmless-fixture only; any future work involving authentic malicious samples must occur only in a separately authorized isolated lab with its own safety and evidence contract.

### B14-0 target — Verified Protection & Independent-Test Readiness Foundation

- freeze the exact Beta13 final checkpoint as the source baseline;
- preserve canonical coverage at `PARTIAL=4 / GAP=0 / VERIFIED=7`;
- define measurable protection / performance / usability evidence gates;
- distinguish existing low-noise microbench evidence from full system-impact testing;
- distinguish scenario-specific VERIFIED detections from broad real-world malware protection;
- keep false-positive, performance and behavioral breadth claims fail-closed until larger evidence exists;
- keep public-release `CODE_SIGNING` blocker factual and separate from protection quality;
- no response-authority expansion, no mandatory network/cloud dependency, no silent destructive remediation;
- no real-malware execution in normal CI/local acceptance.

### Planned Beta14 line

1. **B14-0 — Verified Protection & Independent-Test Readiness Foundation** — 🚧 CURRENT — freeze measurable protection, performance and usability evidence gates without promoting coverage.
2. **B14-1 — Safe Adversary Emulation Matrix** — PLANNED — expand harmless behavior emulation across script abuse, process chains, persistence-like activity, ransomware-like file churn, archives and reputation edge cases; no destructive payload, propagation, credential theft, defense disabling or real-data encryption.
3. **B14-2+ — Evidence-Backed Protection Expansion** — PLANNED — promote only scenarios that earn accepted Windows evidence and keep independent-lab readiness factual.

Current engineering branch:

```text
feature/v014-b140-verified-protection-test-readiness
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
