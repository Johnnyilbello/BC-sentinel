# BC Sentinel v0.7.0-beta.2 — Firewall Rule Observability & Transactional Cleanup Fix

## Scope

This is a narrow corrective release for the v0.7 Windows Firewall foundation. It does not expand firewall privileges or alter global Windows Firewall policy.

## Native issue confirmed on Windows 11

The v0.7.0-beta.1 acceptance probe successfully created BLOCK rules, but the immediate observability check returned `present_after_add=false`. Native PowerShell inspection confirmed the rules existed and were enabled, with a GUID-like rule identity exposed by the PowerShell management layer and the BC Sentinel logical identity present in the display label.

Two beta.1 acceptance probes remained because the test returned before REMOVE after the failed intermediate assertion.

## Fixes

- Firewall identity resolution now accepts the BC Sentinel logical `BCSF-*` id from the friendly Name, DisplayName (when exposed by the management surface), or a machine-readable Description marker.
- Newly-created beta.2 rules include `bcsentinel-rule-id=<BCSF-ID>` in Description as a recovery identity.
- Removal enumerates the exact owned rule, verifies group + BLOCK action + logical rule id, and removes using the native COM identity of that exact rule.
- The acceptance probe polls briefly for post-add/post-remove observability instead of assuming zero-latency propagation.
- The acceptance probe now performs REMOVE inside `finally`, so any rule created by the probe is cleaned up even if a later assertion fails.
- Acceptance records the baseline managed rule set and requires the same logical rule set after cleanup.
- A failed cleanup reports `cleanup_required_rule_id` instead of silently leaving residue.

## Safety properties retained

- BLOCK-only mutation surface.
- No global firewall enable/disable changes.
- No default inbound/outbound policy changes.
- No ALLOW rule creation.
- UAC broker required for mutation from a standard user.
- Exact BC Sentinel group ownership required.
- Explicit operator approval required.
- Broad/loopback/multicast/unspecified network safety guards retained.
- Group Policy / disabled active-profile enforcement fail-safe retained.

## Development verification

- Full suite: 295 passed, 1 skipped on non-Windows development host.
- The skipped test is the native Windows PowerShell parser gate; expected Windows total: 296 passed.
- Python compileall: PASS.

## Native acceptance target

Upgrade from `0.7.0-beta.1` to `0.7.0-beta.2`, then run `tools.firewall_acceptance` from a non-elevated PowerShell. Expected:

- `direct_gate = admin_required`
- `present_after_add = true`
- `remove.ok = true`
- `absent_after_remove = true`
- `baseline_restored = true`
- `passed = true`
