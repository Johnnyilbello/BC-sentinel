# BC Sentinel v0.11.0-beta.7 — B7-0 Local Windows Acceptance

Date: **2026-09-15**

Milestone: **B7-0 — Coverage Ledger Foundation**

Accepted branch:

```text
feature/v011-beta7-b70-coverage-ledger
```

Accepted code commit:

```text
cd06f284525b3e0f70c121b6b97833cbf388c9ce
```

Frozen predecessor:

```text
checkpoint/v011-beta6-b67-pass
eb08758a304eb838d08af890ef9c4786264afbc0
```

Checkpoint created from the exact accepted B7-0 commit:

```text
checkpoint/v011-beta7-b70-pass
```

## Local acceptance result

```text
351 passed, 36 warnings in 11.72s
Predecessor + B7-0 deterministic gate: PASS
Coverage ledger self-check: PASS
BC SENTINEL v0.11.0-beta.7 B7-0 COVERAGE LEDGER FOUNDATION - PASS
```

The warnings were existing PySide6 signal-disconnect runtime warnings and did not fail the acceptance gate.

## Coverage ledger contract

Verified locally:

```text
scenario_count = 6
PLANNED = 6
PARTIAL = 0
VERIFIED = 0
GAP = 0
read_only = true
duplicate_ids_allowed = false
unsupported_positive_claims_allowed = false
untested_success_allowed = false
execution_authority_added = false
general_home_execution_authorized = false
automatic_quarantine = false
automatic_repair = false
automatic_restore = false
```

This means B7-0 introduces the measurement/ledger foundation only. It does not claim attack coverage that has not been verified and does not add remediation execution authority.

## Protected source state

Protected B2 state remained unchanged from the accepted Beta6 checkpoint: **PASS**.

## Windows CI

GitHub Actions run:

```text
34974069631
```

Conclusion: **SUCCESS**

Verified steps:

- dependency setup: PASS
- compile B7-0: PASS
- Beta5 + Beta6 predecessor regression + B7-0 tests: PASS
- coverage ledger self-check: PASS

## Conclusion

B7-0 is **WINDOWS CI + LOCAL WINDOWS ACCEPTED / CLOSED**.

The accepted source state is frozen at:

```text
checkpoint/v011-beta7-b70-pass
cd06f284525b3e0f70c121b6b97833cbf388c9ce
```
