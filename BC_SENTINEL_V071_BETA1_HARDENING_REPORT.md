# BC Sentinel v0.7.1-beta.1 — Development & Security Report

## Objective

Harden the accepted v0.7.0-beta.3 firewall foundation against external rule drift and introduce an explicit, explainable threat-response decision flow without enabling autonomous destructive behavior.

## Architecture changes

### Persistent firewall desired state

The Protection Service database now stores the exact approved shape of BC Sentinel managed rules. Firewall mutation and desired-state persistence are coupled defensively: if desired-state persistence fails immediately after a new rule is created, the exact newly-created rule is rolled back rather than left unmanaged.

### Drift engine

`FirewallManager.drift_report()` compares desired vs observed rules using canonical network equivalence and exact scope fields. It reports missing, disabled, modified, untracked-owned and collision states. Repeated identical drift findings are deduplicated at the event layer.

### Reconciliation

`firewall_reconcile` is a privileged IPC operation. It requires explicit approval and restores only desired BC Sentinel BLOCK rules. Untracked and collision rules are observation-only. Non-owned Windows/third-party rules remain outside the mutation boundary.

### Service monitoring

The existing service hardening cycle invokes the drift engine, giving BC Sentinel ongoing observability without a new privileged background executor.

## Threat Decision Center

The threat dialog now provides four explicit choices: quarantine, permanent delete, keep once, and allow exact hash. Permanent delete is identity-safe: path, reparse status, managed-root protection, file snapshot and SHA-256 are revalidated immediately before unlink. Keep-once creates no persistent trust. Hash trust is intentionally narrow.

## Native acceptance strategy

- v0.7.0 standard-user broker firewall acceptance remains unchanged.
- v0.7.1 adds an elevated drift acceptance using Windows Firewall COM only on one temporary BC-owned TEST-NET rule.
- cleanup is transactional and final managed-rule baseline must match the starting baseline.

## Remaining v0.7.1 hardening work

- mutation/IPC rate limiting;
- richer policy conflict classification across overlapping rules;
- protected UI surface for drift alerts and one-click approved reconciliation;
- service-owned threat decision requests for every detection source;
- Authenticode-valid publisher trust as a separate high-friction action;
- fault injection around desired-state DB failures and reconciliation races;
- large-rule-set latency/performance benchmarks.
