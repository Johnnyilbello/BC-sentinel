# BC Sentinel v0.7.0-beta.2 — Firewall Observability Fix Report

## Finding

Native Windows testing proved the firewall mutation itself worked. Two BLOCK rules targeting `192.0.2.77` existed, were enabled, outbound, and belonged to `BC Sentinel Managed Protection`, while the beta.1 acceptance probe reported `present_after_add=false`.

This exposed two independent weaknesses in the beta.1 acceptance path:

1. Rule identity/observability was too dependent on a single management representation immediately after creation.
2. Cleanup was not transactional: an intermediate assertion failure returned before REMOVE.

## Remediation

### Stable logical identity

`WindowsFirewallBackend` resolves the logical rule id through a narrow ordered strategy:

1. managed prefix in native Name;
2. managed prefix in DisplayName when a management layer exposes it;
3. `bcsentinel-rule-id=<id>` Description marker for beta.2-created rules.

Ownership is still fail-closed: exact managed group, valid `BCSF-*` id, and BLOCK action are all required.

### Exact removal

Removal no longer synthesizes an assumed Windows rule name from the logical id. The backend enumerates the exact owned rule, validates the logical id, and removes that exact native rule identity. This avoids confusing BC Sentinel's logical identity with Windows/CIM-generated identifiers.

### Propagation-aware acceptance

The acceptance harness now polls for up to 5 seconds at 200 ms intervals after ADD and REMOVE. This accommodates the documented small lag around newly-added Windows Firewall rules without weakening the assertion.

### Transactional cleanup

Once ADD returns a logical rule id, REMOVE is attempted in `finally` regardless of whether the observability assertion succeeds. The final set of logical managed rule ids must equal the pre-test baseline.

## Regression tests added

- GUID-like native Name + BC Sentinel DisplayName resolves to the correct logical id.
- Description-marker recovery resolves a valid logical id.
- Removal enumerates and removes the exact owned native rule.
- Acceptance source requires `finally`, polling, baseline tracking, baseline restoration, and cleanup diagnostics.
- New rules carry the machine-readable Description identity marker.

## Development result

`295 passed, 1 skipped` on non-Windows development host. Expected Windows result: `296 passed`.
