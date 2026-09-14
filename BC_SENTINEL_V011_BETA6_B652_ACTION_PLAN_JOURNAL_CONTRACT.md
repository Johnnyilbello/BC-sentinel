# BC Sentinel v0.11.0-beta.6 — B6-5.2 Reversible Action-Plan + Journal Contract

Status: **IMPLEMENTED / WINDOWS CI PENDING**

Development branch:

```text
feature/v011-beta6-b65-guided-resolution
```

Accepted parent checkpoint:

```text
B6-5.1 Passive provider boundary
c442cec4b2554e40a138f46447177dae189d35cc
checkpoint/v011-beta6-b651-pass
```

Stable predecessor:

```text
B6-4 Threat Cards + Advanced Details
c3fbac9e89edff6b08490da3dd593300e816fa30
checkpoint/v011-beta6-b64-pass
stable/v011-beta6-b64
```

Recommended reasoning: **High**. Use **Extra High** for any confirmation, execution, privileged mutation, rollback implementation or change to canonical finding semantics.

## Purpose

B6-5.2 defines an integrity-bound plan for a possible future mutating action without authorizing or executing that action.

The checkpoint answers:

> If a future action such as quarantine or repair were considered, exactly which finding, evidence, target, provider snapshot, rollback requirements and journal requirements would the decision need to be bound to?

It intentionally does not answer "execute now".

## New planning module

```text
sentinel/guided_resolution_action_plan.py
```

Profile/schema:

```text
v0.11.0-beta.6-b65.2-action-plan
bc-sentinel-beta6-guided-resolution-action-plan-v1
```

The module has no execute/apply/remediate API and performs no filesystem writes.

## Source bindings

A B6-5.2 plan is built only from:

1. one validated B6-4 `ThreatCardModel`;
2. the matching validated B6-5.0 `GuidedResolutionModel`;
3. one accepted B6-5.1 passive provider capability snapshot;
4. one known future mutating action identifier.

The plan stores SHA-256 integrity bindings for:

```text
source Threat Card
source Guided Resolution model
provider capability snapshot
```

It preserves canonical severity and canonical confidence exactly, including `None`.

## Target identity

For the first planning checkpoint, a file target is considered strongly bound only when the source finding contains exactly one explicitly SHA-256-labelled digest in its own evidence payload.

States:

```text
VERIFIED_SHA256
UNVERIFIED
AMBIGUOUS
```

If no explicit finding SHA-256 exists, or multiple distinct SHA-256 values exist, the plan fails closed to:

```text
BLOCKED_TARGET_IDENTITY
```

B6-5.2 never chooses between ambiguous hashes and never infers a hash from unrelated scan evidence.

A verified target produces a deterministic target fingerprint from:

```text
target kind + normalized locator + explicit sha256
```

This still does not authorize execution.

## Plan authority

Even a strongly bound plan remains:

```text
plan_status = PLANNED_NOT_AUTHORIZED
authority_state = PLANNING_ONLY
execution_authorized = false
confirmation_issued = false
automatic_action = false
destructive_authority = false
provider_action_available = false
```

The B6-5.1 provider must still report every mutating action as unavailable. B6-5.2 refuses to construct a plan if the passive provider unexpectedly exposes the requested mutating action as available.

## Journal blueprint

Schema:

```text
bc-sentinel-beta6-guided-resolution-journal-blueprint-v1
```

The journal remains a blueprint only:

```text
status = BLUEPRINT_ONLY
storage_binding = NOT_BOUND
```

Required future stages are declared up front:

```text
PLAN_CREATED
PRE_STATE_REQUIRED
CONFIRMATION_REQUIRED
ACTION_STARTED
ACTION_RESULT
POST_STATE_REQUIRED
VERIFY_RESULT
ROLLBACK_STARTED_ON_FAILURE
ROLLBACK_RESULT
FINAL_OUTCOME
```

Future journal requirements include append-only behavior, pre-state, post-state, verification and rollback records. B6-5.2 has no journal write authority.

## Rollback blueprint

Schema:

```text
bc-sentinel-beta6-guided-resolution-rollback-blueprint-v1
```

The rollback contract remains:

```text
status = REQUIRED_NOT_BOUND
rollback_binding = NOT_BOUND
snapshot_required = true
protected_or_external_store_required = true
restore_verification_required = true
rollback_on_failure_required = true
```

No snapshot is created and no rollback is executed in B6-5.2.

## Plan integrity

The complete canonical planning payload is hashed with SHA-256. The `plan_id` is derived from that digest:

```text
B652-<first 16 uppercase hex chars>
```

Validation recomputes the hash and refuses a tampered plan.

## Deterministic tests

New suite:

```text
tests/test_v011_beta6_b652_action_plan.py
```

It proves:

1. B6-5.2 is planning-only and non-executing;
2. a uniquely SHA-256-bound file can produce an integrity-bound, non-authorized plan;
3. source-card, source-resolution and provider snapshots are bound into the plan hash;
4. plan tampering is refused;
5. missing target SHA-256 blocks the plan;
6. multiple target SHA-256 values fail closed as ambiguous;
7. unknown/non-mutating actions are refused as action plans;
8. an unaccepted provider boundary refuses plan construction;
9. journal and rollback remain blueprints only.

## Next gate

After Windows CI is green, B6-5.2 may receive a checkpoint ref. The next milestone is:

```text
B6-5.3 — Explicit user confirmation gate
```

B6-5.3 must bind confirmation to the exact immutable plan hash and must still not introduce automatic execution. A confirmation for one plan must be unusable for another plan, another finding or a changed target identity.
