# BC Sentinel v0.11.0-beta.6 — B6-5.0 Guided Resolution Foundation

Status: **IMPLEMENTED / WINDOWS CI PENDING**

Development branch:

```text
feature/v011-beta6-b65-guided-resolution
```

Parent accepted checkpoint:

```text
B6-4 Threat Cards + Advanced Details
c3fbac9e89edff6b08490da3dd593300e816fa30
checkpoint/v011-beta6-b64-pass
stable/v011-beta6-b64
```

Recommended reasoning: **High**. Use **Extra High** before adding any live remediation provider, privileged mutation, destructive action, or change to canonical finding semantics.

## Purpose

B6-5.0 opens Guided Resolution without granting remediation authority. It answers a narrower first question:

> Given one accepted B6-4 Threat Card, what can BC Sentinel safely recommend right now, and why is any stronger action still unavailable?

This checkpoint is deliberately report-only. It establishes the decision and UX boundary that later B6-5 submilestones must cross before quarantine, repair, deletion, process termination or trust mutation can exist in Home.

## Architecture

New modules:

```text
sentinel/home_guided_resolution.py
sentinel/home_guided_resolution_ui.py
sentinel/home_guided_resolution_window.py
```

New tests:

```text
tests/test_v011_beta6_b650_guided_resolution.py
tests/test_v011_beta6_b650_window.py
```

Windows workflow:

```text
.github/workflows/b65-guided-resolution.yml
```

Profile/schema:

```text
v0.11.0-beta.6-b65.0-guided-resolution
bc-sentinel-beta6-guided-resolution-v1
```

## Decision model

Each accepted B6-4 `ThreatCardModel` produces one `GuidedResolutionModel`.

Canonical data is preserved:

- finding ID;
- severity;
- confidence, including `None`;
- B6-4 Threat Card payload;
- source check evidence;
- scan state and coverage through the source card;
- provider provenance through the source card.

B6-5.0 does not reclassify a threat and does not infer missing confidence.

Review states:

```text
REVIEW_REQUIRED
EVIDENCE_INCOMPLETE
```

Authority state:

```text
REPORT_ONLY
```

The only available capability is:

```text
REVIEW_DETAILS
```

The following capabilities are explicitly represented but unavailable:

```text
QUARANTINE
REPAIR
DELETE
TERMINATE_PROCESS
TRUST_OR_ALLOWLIST
```

## Confidence / safety gate

Advanced resolution details expose the current gate inputs:

```text
canonical confidence
canonical severity
evidence presence / partial state
reversibility = UNVERIFIED
potential damage = UNDEFINED_UNTIL_ACTION_DEFINED
remediation provider boundary verified = false
execution authorized = false
```

If scan coverage is incomplete/cancelled/failed or source-check evidence is missing, the model fails closed to `EVIDENCE_INCOMPLETE`.

Missing confidence remains `UNAVAILABLE`; it is never estimated from severity, signal count or heuristic score.

## UI

Every B6-4 Threat Card gains a passive `Risoluzione guidata` panel showing:

- current review state;
- report-only authority;
- recommended next step;
- explicit statement that no quarantine/repair/delete/process termination is being performed;
- `Dettagli risoluzione` with the exact gate, capability and source-card payload.

No mutating action button is exposed.

The accepted six-page Home shell, Smart Scan coordinator, cancellation flow, provider boundary and B6-4 Advanced details remain unchanged.

## Existing Rescue remediation review

Before opening B6-5 execution authority, the existing Rescue remediation foundations were reviewed at the architectural boundary:

- `sentinel/rescue_repair_engine.py` already enforces explicit plan-bound confirmation, target fingerprint revalidation, external rollback storage, pre/post hashes and rollback-on-failure for a constrained **offline** repair flow;
- `sentinel/rescue_console_guided_repair.py` prepares a trusted offline repair handoff and explicitly records `execution_performed=false`, `automatic_execution=false`, `automatic_repair=false`;
- `sentinel/rescue_recovery_decision.py` preserves `INDETERMINATE`/manual review states and only labels repairable paths when trusted bound evidence exists.

These are valuable foundations, but they are **not** treated as permission to execute Home/live remediation. Offline Rescue authority and live Home authority remain separate until a dedicated B6-5 provider boundary and acceptance gate prove safe reuse.

## Static authority contract

B6-5.0 requires:

```text
authority = REPORT_ONLY
remediation_provider_boundary_verified = false
execution_available = false
automatic_quarantine = false
automatic_repair = false
automatic_destructive_action = false
delete_authorized = false
process_termination_authorized = false
trust_mutation_authorized = false
confirmation_required_for_future_mutation = true
rollback_required_for_future_mutation = true
```

## Planned B6-5 sequence

```text
B6-5.0  Passive decision + Guided Resolution UI        <- current
B6-5.1  Remediation provider boundary/capability probe
B6-5.2  Reversible action-plan + journal contract
B6-5.3  Explicit user confirmation gate
B6-5.4  Harmless/reversible live-action acceptance
B6-5.x  Broader supported action set only after proof
```

No later step may bypass the safety evidence from earlier steps.

## Acceptance gate for B6-5.0

Windows CI must prove:

1. all predecessor deterministic tests remain green;
2. B6-4 self-check remains green;
3. canonical severity/confidence are preserved;
4. incomplete evidence fails closed;
5. only non-mutating review capability is available;
6. no remediation provider is loaded or invoked;
7. no mutation control appears in the B6-5.0 UI;
8. six-page Home shell remains intact;
9. no horizontal overflow regression;
10. offscreen Home smoke passes.

B6-5.0 remains development-only until this gate is observed green on Windows.
