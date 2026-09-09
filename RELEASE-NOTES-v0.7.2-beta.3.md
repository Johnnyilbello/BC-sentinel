# BC Sentinel v0.7.2-beta.3 — Domain Trust, Provenance & Browser Context

## Scope
Beta 3 builds on the native-accepted active Web Protection path by adding a persistent, revocable exact-domain trust policy, explicit verdict provenance, bounded local domain reputation and browser/process context. The release does not expand network enforcement beyond the already accepted temporary BC-owned containment lease model.

## Domain Trust policy
- Persistent trust is **exact-domain only**. Wildcards are rejected and trust never implicitly extends to subdomains.
- Adding or removing persistent trust is a privileged Protection Service operation and uses the existing one-action UAC broker.
- Trust is bounded to 512 exact domains.
- Signed threat intelligence has strict precedence: `signed IOC > local domain trust > local heuristics`.
- A trusted domain that later matches an active signed domain IOC remains present as historical policy state but is marked `overridden_by_signed_ioc`; the signed malicious verdict is authoritative.
- A signed network IOC also remains authoritative regardless of local domain trust because it targets the remote address/network itself.
- Adding trust for a currently signed-malicious domain fails closed.
- Trusting one domain resolves only pending findings for that exact domain; unrelated domains and subdomains are unaffected.

## Verdict provenance
`WebAssessment` now carries structured provenance describing the evidence tier used for the current decision:
- signed IOC bundle id, severity, expiry and label;
- local exact-domain trust reason/source finding;
- local heuristic signal list.

When a signed IOC overrides existing local trust, both evidence tiers are exposed so the operator can see why the local policy did not win.

## Local domain reputation
BC Sentinel now maintains a bounded local domain-reputation aggregate for observed Web Protection events:
- first/last seen;
- observation count;
- maximum observed score;
- malicious/suspicious observation counts;
- latest source/status/process/address;
- bounded samples of up to 16 processes and 16 addresses.

The aggregate store is capped at 20,000 domains; oldest reputation aggregates may be pruned without affecting signed IOC state or domain-trust policy.

## Browser/process context
Known browsers are classified only by exact executable identity (`chrome.exe`, `msedge.exe`, `firefox.exe`, `brave.exe`, `opera.exe`, `opera_gx.exe`, `vivaldi.exe`, `arc.exe`). Signer text is recorded as evidence but never upgrades an arbitrary lookalike executable into a browser.

Network findings persist browser family plus existing process SHA-256, signature status and signer evidence when available.

## Security Center UX
Web Protection Center adds:
- **Dettagli dominio** — local reputation and current provenance;
- **Consenti dominio** — persistent exact-domain trust through UAC;
- **Revoca fiducia** — explicit policy revocation through UAC;
- visible `IOC override fiducia` state when signed intelligence supersedes local trust.

Existing actions remain unchanged:
- `Ignora una volta` is non-persistent;
- `Blocca 15 min` remains a separately approved reversible containment action.

## Safety invariants retained
- no HTTPS MITM, root CA or TLS proxy;
- no heuristic auto-block;
- no wildcard/domain-subtree trust;
- no local-trust override of signed malicious intelligence;
- no automatic permanent web block;
- no third-party/global firewall mutation;
- deterministic protection remains functional without AI/cloud.

## Acceptance
New critical gates:
- `web-trust-v072-beta3-foundation`;
- `web-trust-v072-beta3-live`.

Dedicated acceptance:
- `python -m tools.web_domain_trust_acceptance --service-live`.
