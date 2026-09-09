# BC Sentinel v0.7.1-beta.1 — Firewall Hardening & Threat Decision Center

## Scope

This release starts the v0.7.1 hardening line on top of the native-Windows-accepted v0.7.0-beta.3 firewall foundation. The accepted v0.7.0 BLOCK-only enforcement boundary, UAC broker, Windows Firewall COM backend, transactional updater and anti-downgrade rules remain intact.

## Firewall desired state and drift detection

- Every BC Sentinel-created firewall rule now has a persistent desired-state record in the protected service database.
- Drift comparison is semantic: Windows host forms such as `192.0.2.77`, `/32`, and dotted `/255.255.255.255` are equivalent.
- Drift classes: `missing`, `disabled`, `modified`, `untracked_owned`, and exact-managed-group `collision`.
- Exact-group rules that fail BC Sentinel ownership validation are observed as collisions and are never modified automatically.
- Standard users may read drift status through authenticated IPC.
- Reconciliation is privileged, requires explicit approval, remains BLOCK-only, and acts only on rules already present in BC Sentinel desired state.
- Missing/disabled/modified owned rules can be restored to their exact approved shape.
- Untracked or collision rules are never deleted by reconciliation.
- The Protection Service checks drift during the existing hardening cycle; change events are deduplicated and a cleared event is emitted when policy returns to the expected state.

## Native drift acceptance

A new `tools.firewall_drift_acceptance` gate performs a controlled Windows test:

1. run from elevated PowerShell;
2. create one temporary BC Sentinel TEST-NET rule through the service;
3. alter only that owned rule directly through Windows Firewall COM to simulate external drift;
4. require `disabled` drift observability;
5. explicitly reconcile through the service;
6. require drift clearance;
7. clean up and require the original managed-rule baseline.

No global Windows Firewall state or third-party rule is touched.

## Threat Decision Center

Qualified HIGH/CRITICAL detections now present an explicit response decision instead of only a quarantine/ignore choice:

- **Quarantena · consigliato** — reversible isolation remains the preferred action.
- **Elimina definitivamente** — requires a deliberate confirmation and then revalidates SHA-256 + file snapshot immediately before unlink. BC Sentinel-managed paths and reparse points are refused.
- **Mantieni questa volta** — does not create a persistent exclusion.
- **Consenti hash** — trusts only the exact SHA-256; when the Protection Service owns protection, the exclusion is also sent through the one-action privileged broker before the local UI state is updated.

Each completed UI decision is written as a structured `threat_decision` security event including hash, score, level, action, status and explicit-user-decision marker. Permanent destruction is never automatic in this release.

## Safety properties retained

- no ALLOW/open-port firewall rule creation;
- no global firewall enable/disable or default-policy changes;
- no third-party rule mutation;
- no automatic destructive malware response;
- no publisher-wide trust from a single detection;
- anti-downgrade remains fail-closed;
- quarantine remains encrypted and reversible;
- delete uses identity revalidation immediately before removal.

## Development validation target

- full pytest suite PASS;
- Python compileall PASS;
- native Windows build PASS;
- transactional upgrade `0.7.0-beta.3 -> 0.7.1-beta.1` PASS;
- standard-user `tools.firewall_acceptance` PASS;
- elevated `tools.firewall_drift_acceptance` PASS;
- `tools.windows_acceptance --service-live` requires both v0.7.0 firewall foundation and v0.7.1 drift gates.
