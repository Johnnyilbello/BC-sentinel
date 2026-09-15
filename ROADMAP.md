# BC Sentinel — Canonical Roadmap

**Single source of truth for project status, accepted checkpoints, active milestones, coverage state and forward development.**

Last updated: 2026-09-15

## Repository roadmap rule

`ROADMAP.md` is the **only roadmap file** in the repository.

From this point forward:

- do not create version-specific roadmap files;
- update this file whenever a milestone is opened, materially changed, accepted, frozen or superseded;
- accepted checkpoints remain immutable even when this roadmap advances;
- implementation/status evidence may exist separately, but roadmap state must always be reflected here;
- historical roadmap files are removed from the working tree; Git history preserves them.

---

# Current accepted state

Latest immutable accepted checkpoint:

```text
v0.11.0-beta.7 — Detection Coverage & Incident Intelligence
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Acceptance state:

```text
Beta5  COMPLETE / FROZEN
Beta6  COMPLETE / FROZEN
Beta7  COMPLETE / FROZEN
Beta8  IN PROGRESS
```

Final Beta7 Windows gate:

```text
422 passed, 36 warnings
Windows CI: PASS
Local Windows acceptance: PASS
```

Final Beta7 deterministic core digest:

```text
dcd6a7ff975c2fbdce9549d4af630ab6c252acf26ca7b0c31e0c70e72db8ea4e
```

---

# Non-negotiable safety contract

Unless a future milestone explicitly expands authority and passes a dedicated Windows acceptance gate, the following remain false:

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

`RECOMMEND` is advisory. Missing evidence must never be interpreted as proof of safety. High-impact authority must be earned through explicit evidence, reversibility and acceptance.

---

# Accepted foundation

## Beta3 — Rescue & Recovery foundation ✅

Accepted offline recovery architecture, portable rescue workflows, safe data rescue, reversible repair foundations and integrity certification.

## Beta4 — Guided Rescue Console ✅

Accepted guided evidence inventory, repair handoff, safe data rescue, integrated certification and portable Rescue Console.

## Beta5 — Real-world Rescue hardening ✅

Accepted real-world target discovery, hostile/damaged-system handling, stress hardening, crash-safe resume, recovery decision engine, technician evidence package, controlled real-PC acceptance and Portable Technician Release.

## Beta6 — Unified Home / Technician UX ✅ COMPLETE / FROZEN

Final accepted checkpoint:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

Accepted outcomes include the unified Home security experience, smart scan flow, guided resolution, persistent quarantine/restore behavior, safety-preserving technician UX and portable GUI packaging. Beta6 remains immutable.

## Beta7 — Detection Coverage & Incident Intelligence ✅ COMPLETE / FROZEN

Final accepted checkpoint:

```text
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Accepted milestones:

```text
B7-0  Coverage Ledger Foundation            PASS
B7-1  Sentinel Security Graph Foundation    PASS
B7-2  Incident Correlation Engine           PASS
B7-3  Confidence Gate                       PASS
B7-4  Attack-Chain Acceptance Harness       PASS
B7-5  Explainable Security                  PASS
B7-6  Coverage Expansion Campaign           PASS
B7-7  Windows Acceptance & Freeze           PASS
```

Beta7 established deterministic, evidence-bound incident intelligence without expanding remediation authority.

---

# Current measurable coverage baseline

The accepted Beta7 coverage campaign ends with:

```text
PARTIAL   3
GAP       3
VERIFIED  0
```

Current PARTIAL scenario families:

- `B7-POWERSHELL-001` — suspicious script / PowerShell abuse;
- `B7-PERSISTENCE-001` — persistence;
- `B7-C2-DNS-001` — suspicious DNS/network activity.

Current explicit GAP scenario families:

- `B7-RANSOMWARE-001` — ransomware-like behavior;
- `B7-DEFENSE-EVASION-001` — defense evasion / security-control tampering;
- `B7-CREDENTIAL-001` — credential-access indicators.

Synthetic evidence alone is not VERIFIED coverage. A scenario may be promoted only after a dedicated harmless detector-path acceptance proves the behavior on the target platform.

---

# Innovation program status

```text
I1  Sentinel Security Graph        ✅ accepted in B7-1
I2  Confidence Gate                ✅ accepted in B7-3
I3  Attack Prediction Engine       🟡 planned in Beta8
I4  Reversible Self-Healing        ⏳ future gated authority work
I5  Rescue Continuity              ⏳ future
I6  Deception Mesh                 ⏳ future
I7  Adaptive Local Intelligence    ⏳ future
I8  Explainable Security           ✅ accepted in B7-5
```

---

# Beta8 — Verified Detection & Predictive Defense

## Objective

Beta8 converts the conservative Beta7 coverage baseline into reproducible detector-path evidence and then begins predictive multi-stage defense using the accepted Security Graph and Confidence Gate.

No scenario becomes `VERIFIED` simply because supporting code exists. No predictive output grants remediation authority by itself.

## B8-0 — Beta8 Foundation + New Coverage Baseline 🟡 CURRENT

Purpose: freeze the exact Beta7 final state as Beta8's predecessor and create a deterministic, machine-readable Beta8 starting baseline.

Required outcomes:

- branch only from `checkpoint/v011-beta7-b77-pass` / `4d57f749276c588782147d47078ef4c52d1adc51`;
- preserve Beta6/Beta7 accepted source and safety boundaries unchanged;
- create a machine-readable Beta8 coverage baseline for exactly the six accepted scenario IDs;
- baseline must preserve `PARTIAL=3`, `GAP=3`, `VERIFIED=0` at start;
- bind the baseline to the accepted Beta7 final core digest and B7-6 campaign digest;
- identify the next required acceptance milestone for each scenario;
- mark ransomware, defense-evasion and credential-access as explicit Beta8 verification targets;
- no unsupported positive claims;
- deterministic ordering, stable serialization and SHA-256 baseline digest;
- baseline validation must fail closed on scenario/status/digest/authority tampering;
- no process execution, file mutation, network I/O, credential access, registry mutation or remediation authority added by the baseline engine;
- complete accepted predecessor regression remains green;
- dedicated Windows CI and local Windows acceptance before checkpoint freeze.

Planned checkpoint after acceptance:

```text
checkpoint/v011-beta8-b80-pass
```

## B8-1 — Ransomware-like Detector Acceptance

Build harmless detector-path acceptance using controlled temporary-directory mutation patterns and synthetic canary files. Prove detection behavior without destructive encryption or uncontrolled malware.

Target outcome: promote `B7-RANSOMWARE-001` only if detector-path evidence satisfies the verification contract.

## B8-2 — Defense-Evasion / Tamper Detection

Validate non-privileged, harmless control-tamper indicators against the real detector path without disabling actual security controls.

Target outcome: promote `B7-DEFENSE-EVASION-001` only after reproducible detector acceptance.

## B8-3 — Credential-Access Indicator Detection

Use metadata-only fake credential-access indicators and synthetic fixtures. No real credentials, secrets or credential extraction are allowed.

Target outcome: promote `B7-CREDENTIAL-001` only after safe detector-path acceptance.

## B8-4 — Coverage Verification Campaign

Re-run the six-scenario campaign using accepted B8 detector evidence.

Required outputs:

- explicit per-scenario status;
- exact evidence references;
- false-positive status where measurable;
- time-to-detection where applicable;
- evidence quality;
- platform/build provenance;
- no unsupported `VERIFIED` status.

## B8-5 — Attack Prediction Engine Foundation

Use the accepted Security Graph, incident correlation and temporal evidence to estimate whether an incident is converging toward objectives such as ransomware, persistence, credential access, C2 or defense evasion.

Prediction requirements:

- evidence-driven;
- confidence-scored;
- deterministic baseline path before optional adaptive intelligence;
- explicit uncertainty;
- no automatic execution authority;
- inspectable reasoning and evidence IDs.

## B8-6 — Predictive Multi-Stage Attack Chains

Validate prediction over harmless multi-stage scenarios. Measure how early BC Sentinel recognizes likely harmful objectives relative to the final synthetic stage.

## B8-7 — Beta8 Windows Acceptance & Freeze

Final Beta8 gate:

- Beta5/Beta6/Beta7 regression green;
- all accepted Beta8 detector scenarios reproducible;
- coverage ledger/baseline contains no unsupported claims;
- prediction outputs deterministic and evidence-bound;
- false positive and resource-cost checks included;
- safety contract preserved;
- exact-head Windows CI + local Windows acceptance;
- immutable Beta8 final checkpoint.

---

# Continuous Program A — Detection & Attack Coverage

Every future protection milestone must measure what is actually covered rather than infer protection from feature existence.

Where applicable measure:

```text
Coverage
Precision
Detection speed
Correlation rate
Blocking / interruption rate
False-positive rate
Recovery success
Verification success
Explainability completeness
Evidence completeness
Resource cost
```

Use MITRE ATT&CK mapping when useful, but ATT&CK mapping alone is not proof of coverage.

Full-chain testing should increasingly cover relationships such as:

```text
browser/download
-> script interpreter
-> child process
-> persistence
-> DNS/network
-> harmful objective
```

Testing remains harmless and controlled: safe fixtures, simulations, disposable VMs and controlled offline targets only.

---

# Continuous Program B — Product & Innovation

After Beta8, priorities remain:

- Reversible Self-Healing with explicit authority gates;
- Rescue Continuity between live incidents and offline Rescue;
- local deception/canary signals feeding the Security Graph;
- Adaptive Local Intelligence combining static, behavioral, graph, signer, reputation and historical context;
- Dynamic Analysis / Sandbox with strict host isolation;
- IDS/IPS and remote-service attack indicators;
- Privacy / Safe Banking research;
- Identity Protection;
- VPN / untrusted-network protection;
- production packaging, signed binaries, installer/updater provenance and rollback.

---

# Release and roadmap discipline

For every milestone:

1. start from the exact accepted predecessor checkpoint;
2. define scope and non-negotiable safety boundaries in this `ROADMAP.md`;
3. implement only that scope;
4. update this roadmap in the same milestone change set whenever status or requirements change;
5. run deterministic tests and dedicated Windows CI;
6. run local Windows acceptance;
7. freeze the exact tested code SHA in an immutable checkpoint;
8. only after freeze, advance this roadmap to the next milestone;
9. never move an accepted checkpoint;
10. never claim protection beyond current accepted evidence.

Reasoning policy:

- **Extra High:** authority boundaries, attack-chain acceptance, detector verification, prediction safety and final release gates.
- **High:** coverage baselines, graph/correlation work, tests, explainability, metrics and roadmap maintenance.
