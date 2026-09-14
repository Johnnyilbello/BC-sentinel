# BC Sentinel v0.11.0-beta.6 — B6-5.1 Remediation Provider Boundary

Status: **IMPLEMENTED / WINDOWS CI PENDING**

Development branch:

```text
feature/v011-beta6-b65-guided-resolution
```

Accepted parent checkpoint:

```text
B6-5.0 Passive Guided Resolution
08582e6035da04418ef31311016df9ea8e8a3627
checkpoint/v011-beta6-b650-pass
```

Stable predecessor:

```text
B6-4 Threat Cards + Advanced Details
c3fbac9e89edff6b08490da3dd593300e816fa30
checkpoint/v011-beta6-b64-pass
stable/v011-beta6-b64
```

Recommended reasoning: **High**. Use **Extra High** before introducing any execution API, privileged operation or change to the authority contract.

## Purpose

B6-5.1 creates a fixed, fail-closed provider boundary for Guided Resolution capability discovery.

It answers only:

> Which Guided Resolution capabilities are currently available, and can Home obtain that answer without executing or preparing any remediation action?

B6-5.1 does **not** perform remediation. The accepted provider is intentionally incapable of executing one.

## Fixed provider boundary

New modules:

```text
sentinel/guided_resolution_provider_loader.py
sentinel/guided_resolution_live_provider.py
```

Provider module/factory are fixed:

```text
sentinel.guided_resolution_live_provider
create_provider()
```

No arbitrary module path or dynamic plugin location is accepted.

Provider profile:

```text
v0.11.0-beta.6-b65.1-passive-provider
```

Boundary profile/schema:

```text
v0.11.0-beta.6-b65.1-provider-boundary
bc-sentinel-beta6-guided-resolution-provider-v1
```

## Introspection-only contract

The provider exposes only:

```text
capabilities()
```

The boundary rejects a provider if it exposes a callable execution-style API such as:

```text
execute
apply
remediate
quarantine
repair
delete
terminate_process
```

The passive capability probe must declare:

```text
accepted = true
available = true
side_effect_free_probe = true
execution_available = false
automatic_action = false
destructive_authority = false
```

## Capability truth

Only this action is currently available:

```text
REVIEW_DETAILS
```

It is non-mutating.

The provider must explicitly declare all current mutating action families as unavailable:

```text
QUARANTINE
REPAIR
DELETE
TERMINATE_PROCESS
TRUST_OR_ALLOWLIST
```

Any provider that exposes one of those as available is rejected fail-closed.

## Future mutation requirements

The passive provider also records mandatory requirements for a future mutating checkpoint:

```text
explicit_confirmation_required = true
rollback_required = true
journal_required = true
target_revalidation_required = true
```

These declarations do not authorize an action. They are prerequisites for later B6-5 planning and execution gates.

## Home integration

`B65SecurityOverviewWindow` now performs the fixed passive capability probe during construction and exposes the probe result in its self-check/offscreen-smoke evidence.

The distinction is explicit:

```text
capability_provider_boundary_verified = true    # when passive provider contract passes
remediation_provider_boundary_verified = false
execution_available = false
```

The existing B6-5.0 UI remains report-only. No quarantine, repair, delete, process termination or trust action is added to the Home.

## Fail-closed cases

B6-5.1 rejects:

- missing fixed provider module;
- missing or failing factory;
- missing/failing capability probe;
- missing provider identity/provenance;
- wrong capability schema;
- provider not explicitly accepted/available;
- probe not declared side-effect-free;
- any execution availability;
- any automatic/destructive authority;
- any callable execution API;
- mutating action exposed as available;
- mutating action not marked as mutating;
- missing future confirmation/rollback/journal/target-revalidation requirements.

There is no execution fallback.

## Deterministic tests

New suite:

```text
tests/test_v011_beta6_b651_provider_loader.py
```

It proves:

1. the real fixed passive provider loads and is accepted;
2. no execution-style API exists on the accepted provider;
3. a valid synthetic passive provider is accepted;
4. missing module/factory/None provider fails closed;
5. provider with `execute()` is rejected without calling it;
6. exposed quarantine capability is rejected;
7. false execution or rollback declarations are rejected;
8. capability probe failure is rejected without execution fallback.

The main B6-5 Windows gate also reruns all predecessor deterministic tests, B6-3 acceptance, B6-4 self-check, B6-5.1 self-check and Qt offscreen smoke.

## Next gate

After Windows CI is green, B6-5.1 may receive a checkpoint ref. The next milestone is:

```text
B6-5.2 — Reversible action-plan + journal contract
```

B6-5.2 should still be **planning-only**: define a bounded action plan, evidence binding, target identity, snapshot/journal/rollback requirements and refusal semantics without executing the plan.
