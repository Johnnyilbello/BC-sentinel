# BC Sentinel — Canonical Roadmap

This is the **only roadmap source of truth** for BC Sentinel. Every accepted engineering change, checkpoint transition, roadmap change, and repository-structure change must update this file.

## Current state

```text
Beta5  COMPLETE / FROZEN
Beta6  COMPLETE / FROZEN
Beta7  COMPLETE / FROZEN
Beta8  IN PROGRESS
```

Current milestone:

```text
B8-2 — Defense-Evasion / Tamper Detection
```

Latest accepted engineering checkpoint:

```text
checkpoint/v011-beta8-b81-pass
5d25da3fcb8cd67d9faefbf2440eda19a6086eba
```

Latest accepted repository-structure checkpoint:

```text
checkpoint/v011-beta8-repository-hygiene-pass
c33a06d6487115f5ae080edede75f5e63c6bf188
```

Current canonical coverage baseline remains:

```text
PARTIAL   3
GAP       3
VERIFIED  0
```

B8-1 has produced accepted detector evidence supporting `B7-RANSOMWARE-001` as `PARTIAL`; the canonical aggregate baseline is intentionally not recomputed until B8-4 Coverage Verification Campaign.

## Engineering contract

- Exact acceptance first, immutable checkpoint second.
- An accepted checkpoint is never moved.
- Windows CI and local Windows acceptance must pass on the accepted source state before a milestone is frozen.
- Documentation may advance after a frozen checkpoint, but subsequent engineering work must start from the accepted predecessor required by the roadmap.
- Protected B2 sources stay unchanged unless a later explicit security milestone intentionally supersedes them and passes its own acceptance.
- Security testing uses harmless fixtures, simulations, disposable VMs, and controlled offline targets.
- No protection scenario is promoted to `VERIFIED` without current detector-path acceptance evidence.
- Missing evidence fails closed; synthetic evidence alone is not real-world detector verification.
- Scope is not widened while repairing an acceptance failure.

### Authority boundary

Unless a dedicated future milestone explicitly expands authority and passes acceptance:

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

Established the hardened technician/recovery foundation, hostile-target assessment, stress/recovery validation, evidence packaging, controlled real-PC acceptance, and portable technician release foundations.

### Beta6 — Technician UX and safe guided resolution

**Status: COMPLETE / FROZEN**

Final accepted checkpoint:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

Delivered the technician-facing Windows UI line, Home security overview, Smart Scan UX, threat cards, guided-resolution foundations, quarantine/recovery safety work, and portable GUI acceptance while preserving the no-automatic-remediation boundary.

### Beta7 — Detection Coverage & Incident Intelligence

**Status: COMPLETE / FROZEN**

Final accepted checkpoint:

```text
checkpoint/v011-beta7-b77-pass
4d57f749276c588782147d47078ef4c52d1adc51
```

Accepted milestones:

- **B7-0 — Coverage Ledger Foundation** — machine-readable attack coverage ledger.
- **B7-1 — Sentinel Security Graph Foundation** — typed/provenance-preserving security graph.
- **B7-2 — Incident Correlation Engine** — deterministic, explained incident grouping.
- **B7-3 — Confidence Gate** — advisory `RECOMMEND`, `REVIEW_REQUIRED`, `BLOCKED_INSUFFICIENT_EVIDENCE` outcomes.
- **B7-4 — Attack-Chain Acceptance Harness** — harmless in-memory multi-stage acceptance chain.
- **B7-5 — Explainable Security** — user and technical explanations grounded in evidence IDs.
- **B7-6 — Coverage Expansion Campaign** — explicit PARTIAL/GAP accounting.
- **B7-7 — Beta7 Windows Acceptance & Freeze** — full regression/resource/safety freeze.

Beta7 closed with:

```text
PARTIAL   3
GAP       3
VERIFIED  0
```

## Beta8 — Verified Detection & Predictive Defense

**Status: IN PROGRESS**

Goal: convert explicit coverage gaps into reproducible detector-path evidence first, then build predictive multi-stage reasoning on top of accepted graph/correlation/confidence foundations.

### B8-0 — Beta8 Foundation + New Coverage Baseline ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta8-b80-pass
969781bd7633d0b2bc92840e8f12220f00de4279
```

Acceptance summary:

- compile PASS;
- 450 local Windows tests PASS;
- exact-head Windows CI PASS;
- protected B2 unchanged;
- accepted Beta7 intelligence/final-gate sources unchanged;
- single-roadmap invariant PASS;
- deterministic baseline and round-trip PASS;
- coverage remains `PARTIAL=3 / GAP=3 / VERIFIED=0`;
- no remediation/execution authority added.

Verification targets inherited by Beta8:

1. `B7-RANSOMWARE-001`
2. `B7-DEFENSE-EVASION-001`
3. `B7-CREDENTIAL-001`

### Repository hygiene pass ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta8-repository-hygiene-pass
c33a06d6487115f5ae080edede75f5e63c6bf188
```

Acceptance summary:

- local Windows hygiene gate PASS;
- exact-head Windows CI PASS;
- 450 Beta5/Beta6/Beta7/B8-0 regression tests PASS;
- accepted B8-0 engineering paths unchanged;
- canonical single-roadmap rule PASS;
- root allowlist reduced to 10 files;
- historical test/retest/update/diagnostic/recovery launchers, obsolete patches/checksums, and superseded reports removed from the public working tree;
- `BUILD-V011-BETA6-B67-PORTABLE-GUI.ps1` retained because accepted Beta6 regression tests still bind to that build contract;
- no immutable checkpoint rewritten or moved.

Repository policy from this point forward: keep the public root compact; put engineering tooling under dedicated directories (`sentinel/`, `tests/`, `tools/`, `packaging/`, `.github/`, `coverage/`) unless a root-level file is required by an accepted compatibility contract.

### B8-1 — Ransomware-like Detector Acceptance ✅ ACCEPTED / FROZEN

Accepted source:

```text
checkpoint/v011-beta8-b81-pass
5d25da3fcb8cd67d9faefbf2440eda19a6086eba
```

Acceptance summary:

- local Windows acceptance PASS;
- exact-head Windows CI PASS;
- 462 Beta5/Beta6/Beta7/B8-0/B8-1 tests PASS;
- protected B2 unchanged;
- accepted B8-0 baseline sources unchanged;
- repository-hygiene contract PASS;
- positive ransomware-like fixture => `DETECTED`;
- backup-like fixture => `REVIEW_REQUIRED`, never `DETECTED`;
- benign fixture => `NO_MATCH`;
- deterministic serialization and stable round-trip PASS;
- evidence IDs preserved into Security Graph and Incident Correlation;
- detection latency in controlled fixture = 2.0 seconds;
- accepted detector evidence status for `B7-RANSOMWARE-001` = `PARTIAL`;
- `VERIFIED` remains prohibited because the milestone uses synthetic in-memory fixtures only;
- all execution/remediation authority flags remain false.

### B8-2 — Defense-Evasion / Tamper Detection 🟡 CURRENT

Objective: validate safe detector coverage for defense-evasion/control-tampering indicators with explicit provenance and false-positive controls, targeting `B7-DEFENSE-EVASION-001`.

Required acceptance properties:

- harmless normalized/synthetic indicators only;
- no actual security-control disabling or registry/service mutation;
- explicit evidence IDs and provenance;
- deterministic scoring and stable serialization;
- negative fixtures for legitimate configuration/admin activity;
- Security Graph + Incident Correlation integration;
- measurable detection latency/resource cost;
- scenario may move only as far as accepted evidence supports;
- no automatic quarantine/repair/restore, process termination, trust mutation, delete, repair, or privileged mutation authority.

### B8-3 — Credential-Access Indicator Detection

Validate safe, non-secret-stealing indicators associated with credential-access behavior. Fixtures must not extract or expose real credentials.

### B8-4 — Coverage Verification Campaign

Recompute the coverage ledger from accepted B8 detector evidence. Promote only scenarios that meet the verification contract; unresolved scenarios remain explicit GAP/PARTIAL.

### B8-5 — Attack Prediction Engine Foundation

Use accepted graph/correlation sequences to estimate likely next attack stages without inventing evidence or granting execution authority.

### B8-6 — Predictive Multi-Stage Attack Chains

Validate prediction across controlled multi-stage chains such as script -> persistence -> discovery/network -> impact indicators, with confidence/calibration and explainability.

### B8-7 — Beta8 Windows Acceptance & Freeze

Full Windows regression and exact-head CI/local freeze for Beta8, including detector evidence, coverage state, predictive reasoning, safety boundaries, determinism, resource cost, and immutable final checkpoint.

## Longer-term innovation programs

The following remain roadmap programs rather than current accepted protection claims:

- **I3 — Attack Prediction Engine** — begins in Beta8 after detector evidence exists.
- **I4 — Reversible Self-Healing** — any automatic repair authority requires a dedicated safety milestone.
- **I5 — Rescue Continuity** — preserve incident/evidence identity across live Windows and Rescue workflows.
- **I6 — Deception Mesh** — local canary/decoy signals integrated into evidence/graph reasoning.
- **I7 — Adaptive Local Intelligence** — fuse static, behavior, signer, graph, reputation, and local context.
- Dynamic analysis/sandboxing, IDS/IPS expansion, identity protection, privacy/safe-banking controls, untrusted-network protection, and production packaging remain future work.

## Repository/documentation policy

- `ROADMAP.md` is the single roadmap file.
- `README.md` is the public landing page, not a second roadmap.
- `SECURITY.md` contains security/disclosure guidance.
- `STABLE-RELEASE.md` documents the separately promoted stable channel.
- Historical development evidence remains recoverable from Git history and immutable checkpoint refs.
- Every future milestone/status change updates this `ROADMAP.md` in the same development cycle.
