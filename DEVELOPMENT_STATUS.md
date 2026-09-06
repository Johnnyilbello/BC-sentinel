# BC Sentinel — Development Status

Last updated for development line **v0.8.0-beta.1**.

## Current status

BC Sentinel is an **actively developed Windows endpoint-security project**. It is currently a development preview, not a production security product.

Do not disable Microsoft Defender or Windows Firewall in order to test BC Sentinel. The project is being designed to coexist with the native Windows security stack during development and acceptance testing.

## Current milestone

`v0.8.0-beta.1 — Signed Threat Intelligence & Secure Update Channel`

The v0.8.0-beta.1 development snapshot introduces:

- Ed25519-signed threat packages;
- IOC/YARA/advisory behavior package components;
- component hash and validity verification;
- sequence anti-rollback protection;
- staged validation and atomic activation;
- last-known-good rollback;
- machine-authenticated package state and transparency history;
- threat-package IOC overlay for existing scanner/network/web detection paths;
- YARA hot reload with fail-safe retention of the last valid compiled ruleset;
- a separate signed application-release envelope foundation for the future production updater.

Threat packages cannot execute arbitrary scripts, commands or binaries.

## Native Windows acceptance status

The v0.7 line established and exercised the core Windows security boundaries, including:

- hardened Protection Service;
- Named Pipe authentication and remote-client rejection;
- one-action UAC broker;
- service/update integrity controls;
- managed BLOCK-only firewall rules;
- firewall drift/reconciliation and conflict checks;
- signed IOC feeds and reversible containment;
- Security Center threat decisions;
- DNS/process-correlated Web Protection;
- shared-IP/CDN safety gating;
- exact-domain trust with signed IOC precedence;
- browser/download provenance and Web Incident Chain.

The current **v0.8.0-beta.1** must complete its own native Windows acceptance before it is marked as frozen/accepted. Passing unit/regression tests alone is not treated as production evidence.

## Not yet claimed

BC Sentinel does not currently claim to provide:

- production-grade EDR;
- kernel minifilter protection;
- full Windows Filtering Platform IDS/IPS enforcement;
- production sandbox detonation;
- mature cloud reputation coverage;
- HTTPS MITM inspection;
- Protected Process Light anti-tamper;
- guaranteed pre-execution blocking for every threat class;
- production signed installer/updater enforcement;
- macOS parity;
- enterprise production readiness.

## Safety model

Current safety rules include:

- signed malicious IOC evidence overrides local domain/hash trust;
- heuristic-only Web findings do not auto-block;
- DNS-only evidence is not enough for address containment;
- shared/CDN IPs fail closed for domain-derived containment;
- destructive file actions require the protected Threat Decision path;
- firewall mutations are restricted to BC Sentinel-owned BLOCK rules;
- global Windows Firewall policy and third-party firewall rules are not modified;
- private signing keys are never shipped with the application;
- AI is not required for deterministic protection decisions.

## Testing

Use harmless fixtures, TEST-NET addresses and disposable test environments. Do not intentionally expose a normal workstation to live malware just to test BC Sentinel.

For detailed technical progress, see `ROADMAP.md`, `RELEASE-NOTES-v0.8.0-beta.1.md` and `BC_SENTINEL_V080_BETA1_SIGNED_THREAT_INTELLIGENCE_REPORT.md`.
