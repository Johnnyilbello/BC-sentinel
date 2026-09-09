# BC Sentinel v0.7.0-beta.1 — Firewall & Network Threat Prevention Foundation

Release line: **Beta**  
Platform target: **Windows 11 / Windows 10 (64-bit)**

## Purpose

v0.7.0-beta.1 introduces the first active network-containment layer in BC Sentinel. The release uses the supported Windows Firewall COM policy surface and deliberately keeps the mutation boundary narrow: BC Sentinel creates and manages only its own BLOCK rules and does not alter global Windows Firewall defaults.

## New capabilities

- Windows Firewall backend using `HNetCfg.FwPolicy2` / `HNetCfg.FWRule`.
- BC Sentinel-owned rule group: `BC Sentinel Managed Protection`.
- Closed managed-rule namespace: `BCSF-<16 hex>`.
- Remote IPv4/IPv6 host and CIDR blocking.
- Inbound/outbound direction.
- TCP/UDP/ANY protocol; optional remote port for TCP/UDP.
- Optional per-application executable scope using absolute local Windows paths.
- Read-only firewall posture and managed-rule enumeration for standard users.
- Add/remove/enable-disable mutations routed through the v0.6.2 one-action UAC broker.
- Firewall events feed the existing SecurityEvent / correlation / incident path.
- Incident-linked firewall actions are recorded in the protected response audit.
- Live Windows Firewall readiness probe in the main Windows acceptance suite.
- Dedicated standard-user → UAC → firewall add/remove acceptance using TEST-NET-1 (`192.0.2.77`).

## Safety boundaries

The beta intentionally does **not**:

- disable or enable Windows Firewall globally;
- change default inbound/outbound actions;
- create ALLOW/open-port rules;
- remove or edit non-BC-Sentinel rules;
- override Group Policy;
- use `netsh`, shell commands, or a generic privileged executor;
- install a kernel/WFP callout driver;
- perform autonomous network containment without explicit approval.

The policy layer rejects loopback, multicast, unspecified/default-route networks (`0.0.0.0/0`, `::/0`) and overly broad CIDRs (broader than `/8` for IPv4 or `/16` for IPv6).

Before installing or re-enabling managed blocks, the Windows backend checks that active Windows Firewall profiles are enabled and that `LocalPolicyModifyState` reports an effective local policy. If not, the action fails closed instead of pretending that the block is effective.

## Validation status

Development environment:

- `290 passed, 1 skipped` — the only skip is the native Windows PowerShell parser acceptance.
- `compileall` PASS.
- Static firewall audit: no `subprocess`, `os.system`, `Popen`, `shell=True`, `netsh`, or assignments to global firewall defaults/profile enablement in firewall modules.

Expected native Windows suite after extraction: **291 passed** before build/installation.

## Native acceptance gates

1. Full pytest suite: 291 passed expected on Windows.
2. Build Protection Service + UAC Broker + Firewall.
3. Transactional upgrade from v0.6.2-beta.4 to v0.7.0-beta.1.
4. `tools.windows_acceptance --service-live`: requires `firewall-v070-foundation` and `firewall-v070-live` PASS.
5. `tools.firewall_acceptance` from non-elevated PowerShell: creates one temporary outbound BLOCK to TEST-NET-1 and removes it via two one-action UAC approvals.
6. Final 5000-file/realtime performance gate after functional acceptance.

## Not yet production firewall/IPS

This beta is the managed-firewall foundation. Deeper Windows Filtering Platform telemetry/callouts, rule drift reconciliation, IOC-driven containment leases, IDS/IPS prevention, phishing/web filtering and brute-force defenses remain roadmap work and must earn their own native acceptance evidence.
