# BC Sentinel v0.7.2-beta.2 — Active Web Protection & DNS Threat Response

## Scope
Beta 2 turns the accepted v0.7.2-beta.1 Web Protection telemetry foundation into an explicitly controlled, reversible response workflow. Detection and enforcement remain separated: ETW/network telemetry produces evidence, the Protection Service persists an actionable finding, and only a privileged operator-approved action may create a temporary BC-owned firewall BLOCK rule.

## Active Web Protection
- DNS correlation remains strictly PID-scoped and short-lived.
- `DNSCorrelationCache` now retains bounded recent per-IP history in addition to the exact `(PID, IP) -> domain` mapping.
- The cache exposes shared-infrastructure context: number of recent domains/processes per IP and a conservative `shared_ip` signal.
- `NetworkMonitor` enriches process connections with DNS context and Web Protection verdicts without mutating network policy itself.
- Signed domain IOC evidence may recommend containment only when the current resolved IP is not shared.
- Signed network IOC evidence targets the address itself and may still recommend containment even when the address has been observed for multiple domains.
- Local phishing heuristics remain advisory and below the HIGH/CRITICAL enforcement threshold.

## Shared CDN / hosting safety gate
A malicious-domain finding is not enough to block a shared IP. Before a domain-derived containment lease is created, the Protection Service requires an actually observed same-PID network connection and then rechecks:
1. the finding is still pending and HIGH/CRITICAL;
2. the signed domain IOC is still active;
3. the same PID still has a live DNS correlation to the same domain and IP;
4. the IP has not become shared across multiple recently observed domains;
5. the persisted finding came from a network connection event, not a DNS-only resolution.

DNS-only findings remain pending/observable and cannot create address containment by themselves.
5. the operator explicitly approved the action.

If any check fails, the containment request fails closed and no firewall rule is created.

## Persistent Web Findings
A dedicated `web_findings` store now keeps actionable Web Protection state independently from raw ETW history. Findings include:
- stable `BCW-*` finding id;
- domain / resolved address;
- PID, process name and process path;
- score, level, source and reasons;
- shared-IP evidence and block eligibility;
- current decision/status;
- linked containment lease and resolution metadata.

Repeated pending observations for the same domain/address/PID are deduplicated within a bounded window rather than creating an alert storm.

## Operator decisions
- **Ignora una volta** / reviewed decisions require an authenticated local Windows identity but no UAC elevation; they do not create allowlists or durable trust.
- **Blocca 15 min** uses the existing one-action UAC broker and a new narrow `web_containment_create` operation accepting only a persisted finding id, TTL and reason.
- Web containment TTL is bounded to 60–3600 seconds.
- The service revalidates live IOC/DNS/shared-IP state at action time.
- Lease release/expiry updates the linked Web Protection finding and restores the firewall baseline.

## Security Center UX
The Web Protection Center now exposes persistent findings, status and operator actions. A finding that is on shared/CDN infrastructure visibly disables the address-block action. The UI explains that BC Sentinel will not block an entire shared address from domain-only evidence.

## Benchmark hardening
The Windows acceptance harness now records a 3-run application-cache cold/warm benchmark and reports medians and ranges. This prevents a single antivirus/I/O spike from being mistaken for a stable scanner performance regression while retaining the original per-phase profile.

## Safety invariants retained
- no HTTPS MITM;
- no root certificate installation;
- no TLS proxy or content decryption;
- no heuristic phishing auto-block;
- no global Windows Firewall policy mutation;
- no ALLOW/open-port rule creation;
- only BC Sentinel-owned reversible BLOCK rules;
- privileged enforcement remains behind the authenticated Protection Service/UAC boundary.

## Acceptance
New critical gates:
- `web-response-v072-beta2-foundation`;
- `web-response-v072-beta2-live`.

New non-critical performance posture:
- `performance-v072-beta2-median`.

Dedicated acceptance:
- `python -m tools.web_threat_response_acceptance --service-live`.
