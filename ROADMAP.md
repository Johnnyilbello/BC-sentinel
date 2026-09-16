# BC Sentinel — Canonical Roadmap

This is the **only roadmap source of truth** for BC Sentinel. Accepted engineering checkpoints are immutable. Documentation may advance after an engineering freeze, but no accepted checkpoint is moved.

## Current state

```text
Beta5  COMPLETE / FROZEN
Beta6  COMPLETE / FROZEN
Beta7  COMPLETE / FROZEN
Beta8  COMPLETE / FROZEN
Beta9  COMPLETE / FROZEN
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta9-b94-pass
cc32c2c31ebb9b863624632a38175ec5825430e4
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

This `VERIFIED` status is limited to the accepted controlled live local detector path. It is **not** a claim of broad ransomware-family protection. PowerShell, persistence, defense-evasion, DNS/C2 and credential-access scenarios remain `PARTIAL` until their own accepted live positive controls exist.

## Engineering contract

- Exact acceptance first, immutable checkpoint second.
- Windows CI and local Windows acceptance must pass on the same engineering commit before freeze.
- Missing evidence fails closed; synthetic evidence alone cannot support `VERIFIED`.
- Predictions are advisory and are never evidence.
- Security testing uses harmless fixtures, simulations, controlled temporary resources and disposable/offline targets.
- Scope is not widened while repairing acceptance failures.
- No protection claim may exceed the exact evidence demonstrated by its accepted milestone.

### Authority boundary

Unless a dedicated later milestone explicitly expands authority and passes acceptance:

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

**Status: COMPLETE / FROZEN**

Established hardened technician/recovery workflows, hostile-target assessment, stress/recovery validation, evidence packaging, controlled real-PC acceptance and portable technician foundations.

### Beta6 — Technician UX and safe guided resolution

**Status: COMPLETE / FROZEN**

Final checkpoint:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

Delivered the technician-facing Windows UI line, Home security overview, Smart Scan UX, threat cards, guided-resolution foundations, quarantine/recovery safety work and portable GUI acceptance while preserving the no-automatic-remediation boundary.

### Beta7 — Detection Coverage & Incident Intelligence

**Status: COMPLETE / FROZEN**

Final checkpoint:

```text
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Delivered the coverage ledger, Security Graph, Incident Correlation, Confidence Gate, attack-chain acceptance harness, explainable security and explicit coverage accounting. Beta7 closed at `PARTIAL=3 / GAP=3 / VERIFIED=0`.

## Beta8 — Verified Detection & Predictive Defense

**Status: COMPLETE / FROZEN**

Final checkpoint:

```text
checkpoint/v011-beta8-b87-pass
3c32157dd0c6bb852438319766a9345b0b9f5f1e
```

Accepted line:

- B8-0 foundation / coverage baseline — `checkpoint/v011-beta8-b80-pass`
- B8-1 ransomware-like detector — `checkpoint/v011-beta8-b81-pass`
- B8-2 defense-evasion / tamper detector — `checkpoint/v011-beta8-b82-pass`
- B8-3 credential-access indicators — `checkpoint/v011-beta8-b83-pass`
- B8-4 coverage verification — `checkpoint/v011-beta8-b84-pass`
- B8-5 attack prediction foundation — `checkpoint/v011-beta8-b85-pass`
- B8-6 predictive multi-stage chains — `checkpoint/v011-beta8-b86-pass`
- B8-7 Windows acceptance & freeze — `checkpoint/v011-beta8-b87-pass`

Beta8 established deterministic detector evidence and predictive reasoning but deliberately retained `PARTIAL=6 / GAP=0 / VERIFIED=0` because its detector evidence was synthetic/in-memory.

## Beta9 — Real Windows Telemetry & Detector Verification

**Status: COMPLETE / FROZEN**

Goal achieved: privacy-minimal local Windows telemetry plus reproducible real-path acceptance without adding remediation or privileged authority.

### B9-0 — Windows Telemetry Foundation ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta9-b90-pass
a5a6b08b5e9edfea4d0ce6021f8c9bdab9c5b9b0
```

Read-only inventory of allowlisted Windows channel configuration. No event payloads, user data, channel mutation, elevation or remediation. Local and CI acceptance PASS; canonical coverage remained `PARTIAL=6 / GAP=0 / VERIFIED=0`.

### B9-1 — Bounded Metadata Event Reader ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta9-b91-pass
c4cf63fb0c61e9fc65287b624cb0f59c0cf74c69
```

Added explicit opt-in, local-only bounded metadata reads with fixed channel/provider/event-ID allowlists, event-count bounds and query timeouts. Event messages, XML, payloads, usernames, paths, command lines and script contents remain excluded.

Acceptance:

- CI run `35093305720` PASS on exact SHA;
- local Windows PASS on the same SHA;
- `615 passed, 36 warnings` locally;
- local profile states: System `EMPTY`, PowerShell `EMPTY`, Defender `EMPTY`, Sysmon `UNSUPPORTED`, Security `ACCESS_DENIED`;
- event readability proven; detector verification still false;
- coverage remained `PARTIAL=6 / GAP=0 / VERIFIED=0`.

### B9-2 — Harmless Event-to-Incident Acceptance ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta9-b92-pass
7359f780f206b36355dcb3f6ba3687ad75240b98
```

A harmless local PowerShell engine exercise proved fresh Windows event provenance and binding through a benign acceptance detector, Security Graph and Incident Correlation without reading event message/script payload content.

Acceptance:

- Windows CI PASS and local Windows PASS on the same SHA;
- `691 passed, 36 warnings` locally;
- `live_event_bound=true`;
- event → acceptance detector → Security Graph → Incident Correlation binding PASS;
- no threat classification or detector verification claimed;
- coverage remained `PARTIAL=6 / GAP=0 / VERIFIED=0`.

### B9-3 — False-Positive Controls & Coverage Decisions ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta9-b93-pass
50bbe099ba146201864b8969c91149497df913fa
```

Controlled live filesystem exercises ran only inside dedicated temporary directories and were observed through the accepted ransomware-like detector path.

Accepted local control outcomes:

```text
positive-ransomware-like      24 writes / 18 renames  -> DETECTED
administrative-backup-like    24 writes / 18 renames  -> REVIEW_REQUIRED
benign-save                    2 writes /  0 renames  -> NO_MATCH
```

Acceptance:

- CI run `35097343311` PASS and local Windows PASS on the exact same SHA;
- `715 passed, 36 warnings` locally;
- cleanup `CLEAN` for all controls;
- no real malware, user-file access, file-content collection, remote access or remediation authority;
- synthetic fallback not used;
- Security Graph / Incident Correlation binding PASS;
- `B7-RANSOMWARE-001` promoted to `VERIFIED` only for this controlled live detector path;
- canonical coverage changed to `PARTIAL=5 / GAP=0 / VERIFIED=1`.

The remaining five scenarios stay `PARTIAL` with explicit blockers: no accepted live positive control for PowerShell, persistence, defense-evasion, DNS/C2 or credential access within the current privacy/authority boundary.

### B9-4 — Beta9 Windows Acceptance & Freeze ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta9-b94-pass
cc32c2c31ebb9b863624632a38175ec5825430e4
```

Final acceptance recomposed B9-0 through B9-3 in one Windows gate, re-running the live telemetry/event/control paths instead of relying on historical PASS state.

Final CI acceptance:

- run `35099242292` PASS on exact SHA `cc32c2c31ebb9b863624632a38175ec5825430e4`;
- `721 passed, 36 warnings`;
- independently measured live pipeline: `9.330371 s`;
- composition elapsed: ~`0.00736 s`;
- composition peak memory: `38354 bytes`;
- deterministic core PASS;
- final coverage `PARTIAL=5 / GAP=0 / VERIFIED=1`;
- verified scenario `B7-RANSOMWARE-001`;
- all privacy, no-remediation, no-privileged-mutation and no-broad-protection boundaries PASS.

Final local Windows acceptance on the same SHA:

- `721 passed, 36 warnings`;
- independently measured live pipeline: `5.586691 s`;
- composition elapsed: ~`0.00544 s`;
- composition peak memory: `38488 bytes`;
- deterministic core PASS;
- all three temporary filesystem controls cleaned successfully;
- final coverage `PARTIAL=5 / GAP=0 / VERIFIED=1`;
- final line: `BC SENTINEL v0.11.0-beta.9 B9-4 WINDOWS FINAL ACCEPTANCE & FREEZE - PASS`.

Beta9 is therefore **COMPLETE / FROZEN**. No further Beta9 engineering change is permitted without opening a new explicit milestone/version line.

## Longer-term programs

Future work remains separate from accepted Beta9 claims, including reversible self-healing, rescue continuity, deception/canary expansion, adaptive local intelligence, broader real detector verification, sandboxing/dynamic analysis, network IDS/IPS, identity protection and production packaging.

## Repository/documentation policy

- `ROADMAP.md` is the single roadmap file.
- `README.md` is the public landing page, not a second roadmap.
- `SECURITY.md` contains security/disclosure guidance.
- `STABLE-RELEASE.md` documents the separately promoted stable channel.
- Historical engineering evidence remains recoverable from Git history and immutable checkpoint refs.
- Every future milestone/status change must update this file in the same development cycle.
