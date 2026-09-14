# BC Sentinel v0.11.0-beta.6 — B6-5.5 Local Device Acceptance

Date: 2026-09-14
Branch: `feature/v011-beta6-b65-guided-resolution`
Local tested head before this evidence-only documentation commit: `fdeea5c34bf44a82e2df3b692396a887c5f091f1`

## Result

**PASS — harmless fixture execution + verified rollback on the user's Windows device.**

The operator ran the one-command B6-5.5 acceptance launcher locally with explicit fixture confirmation enabled.

Reported acceptance output:

```text
checkpoint = B6-5.5-harmless-fixture-execution
passed = true
fixture_only = true
journal_passed = true
restored_state_verified = true
cleanup_verified = true
error = null
live_home_execution_authorized = false
```

The launcher also reported:

```text
Self-check: PASS
B6-5.5 harmless fixture execution + rollback acceptance PASS.
Rollback verificato: True
Journal verificato: True
Cleanup verificato: True
Live Home execution autorizzata: False
```

## Scope proved by this acceptance

This local-device run verifies only the dedicated B6-5.5 harmless fixture path:

- a test-owned file is created under `%TEMP%\BCSentinel-B655-*`;
- the provider is restricted to the exact fixture scope;
- the target is bound to SHA-256;
- the fixture is quarantined;
- the journal chain is verified;
- rollback restores the original bytes/hash;
- cleanup succeeds;
- normal Home execution authority remains disabled.

This does **not** authorize quarantine of arbitrary existing user files, system files, privileged locations, repair, delete, process termination, trust/allowlist mutation or automatic remediation.

## Acceptance conclusion

B6-5.5 now has both:

1. GitHub-hosted Windows CI acceptance (`34855442176`) — PASS;
2. local Windows device acceptance using the one-command launcher — PASS.

B6-5.5 is therefore closed for its declared fixture-only scope. The next milestone is B6-5.6, which must introduce a separately gated real-file quarantine boundary while preserving explicit confirmation, exact target identity, journal integrity, rollback verification and fail-closed path eligibility.
