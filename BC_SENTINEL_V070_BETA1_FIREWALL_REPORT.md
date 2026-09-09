# BC Sentinel v0.7.0-beta.1 — Firewall Foundation Development & Security Report

## Executive result

The v0.7 firewall foundation is implemented on top of the accepted v0.6.2 Protection Service, hardening, privileged broker and transactional updater. It adds a narrow, reversible Windows Firewall control plane designed to become the enforcement substrate for later network threat prevention while avoiding global policy takeover.

Development gate: **290 passed, 1 skipped**, plus Python `compileall` PASS. The single skipped test is Windows-only and is expected to run on the target machine.

## Architecture

### Policy layer

`sentinel/firewall_policy.py` owns validation, canonical rule construction, event emission and backend abstraction. The public mutation surface is intentionally BLOCK-only.

Input controls include:

- strict IPv4/IPv6 parsing and canonicalization;
- rejection of loopback, multicast, unspecified/default-route and dangerously broad networks;
- direction allowlist (`inbound`, `outbound`);
- protocol allowlist (`any`, `tcp`, `udp`);
- port range validation and protocol/port consistency;
- absolute local Windows application paths only;
- bounded reason/incident identifiers;
- generated closed `BCSF-*` rule IDs.

### Windows backend

`sentinel/firewall_windows.py` uses Windows Firewall COM objects from the LocalSystem Protection Service. Ownership requires the exact BC Sentinel group, name prefix and BLOCK action. Removal refuses a rule that does not satisfy ownership checks.

The backend does not alter Windows Firewall global enablement or default inbound/outbound policy. Enabling/adding managed rules first checks active profile state and local-policy effectiveness; cleanup/removal remains possible even when enforcement readiness is degraded.

### Privilege boundary

Firewall reads are available to authenticated local standard clients. Mutations are privileged protocol operations and therefore inherit the v0.6.2 security model:

standard client → direct denial (`admin_required`) → server-side validated single-use ticket → UAC broker → elevated local identity verification → exact action → result/audit.

There is no generic command/shell path.

### Incident integration

Firewall rule creation emits structured firewall security events. When an incident ID is supplied, the Protection Runtime also records the containment action through the existing incident-action persistence/audit path. This allows later EDR automation to reason over the same evidence graph instead of operating a separate firewall silo.

## Windows Firewall effectiveness gate

A rule being present is not enough to claim protection. v0.7 therefore checks:

- active profile types;
- `FirewallEnabled` for every active profile;
- `LocalPolicyModifyState`;
- `enforcement_ready` exposed in firewall status.

The live acceptance gate fails if `enforcement_ready` is false. BC Sentinel does not attempt to override enterprise Group Policy or silently turn Windows Firewall back on.

## Acceptance design

### Side-effect-free foundation gate

The main acceptance suite exercises policy/protocol/broker behavior with an in-memory backend, proving admin gating, exact broker action execution, managed rule creation and cleanup without changing host networking.

### Live read-only gate

With `--service-live`, the suite queries the installed service and requires:

- backend `windows_firewall_com`;
- exact managed group;
- no global-policy modification marker;
- `enforcement_ready == true`.

### Explicit mutation gate

`tools/firewall_acceptance.py` must start from a non-elevated PowerShell. It uses only `192.0.2.77` (TEST-NET-1), verifies direct standard-user denial, obtains UAC approval to add one outbound BLOCK rule, confirms the rule is observable, obtains a second UAC approval to remove it, and verifies service/hardening/firewall health after cleanup.

## Security non-goals for beta.1

- no automatic ALLOW rules;
- no arbitrary firewall commands;
- no all-Internet block through the v0.7 API;
- no third-party rule mutation;
- no Group Policy bypass;
- no kernel driver or custom WFP callout;
- no claim of IDS/IPS capability yet;
- no cloud dependency required for deterministic firewall enforcement.

## Next v0.7.x hardening

After native beta.1 acceptance:

- rule drift detection/reconciliation;
- mutation/IPC rate limiting;
- policy conflict detection;
- signed IOC denylist ingestion;
- bounded and reversible incident-driven containment leases;
- large-rule-set and latency benchmarks;
- WFP telemetry prototype for the future IDS/IPS line.
