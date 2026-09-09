# BC Sentinel v0.7.2-beta.1 — Web Protection Security Development Report

## Security objective
Add useful anti-phishing/domain intelligence without creating a browser interception stack or weakening the accepted firewall/service boundary.

## Architecture
### DNS telemetry
The Protection Service attempts to subscribe to the Windows DNS Client ETW provider in the same protected runtime that already owns process/file ETW. DNS setup is optional at runtime: if the provider cannot be started, process/file telemetry remains available and the status reports DNS tracking as unavailable rather than pretending protection exists.

### PID-scoped correlation
`DNSCorrelationCache` records `(PID, resolved IP) -> domain` for a bounded TTL. A connection can inherit a domain only when its process PID matches the process that produced the DNS observation. This deliberately avoids global IP-to-domain inference, which is unsafe on CDNs and shared hosting.

### Web decision model
`WebProtectionEngine` has two evidence classes:
1. **Signed IOC domain evidence** — deterministic malicious verdict, HIGH/CRITICAL score, containment recommendation.
2. **Local structural heuristics** — explainable review signals only, hard-capped below score 50 and therefore below the HIGH/CRITICAL response threshold.

The engine never creates a firewall rule. It only returns an assessment.

## URL/domain heuristics
Beta 1 locally inspects normalized HTTP/HTTPS URLs for bounded structural indicators such as Punycode/IDN, excessive subdomain depth, unusual hostname length/hyphenation, raw IP hostnames and URL userinfo. These are not treated as proof of phishing.

## IPC/API surface
Read-only Protection Service operations:
- `web_status`
- `web_findings`
- `web_assess`

They follow the existing local-installation-token read contract. No new privileged generic mutation endpoint is introduced.

## UI
- Protection card: Web Protection / Anti-Phishing posture, DNS ETW state and explicit no-MITM/no-auto-block wording.
- Security Center: recent web findings and manual domain/URL assessment.
- HIGH/CRITICAL web events may notify the operator, but Beta 1 does not auto-enforce them.

## Acceptance invariants
The release must prove:
- signed domain IOC can produce `containment_recommended`;
- heuristic-only URL analysis remains below score 50;
- DNS correlation never crosses PID boundaries;
- malformed/non-IP DNS result tokens are rejected;
- web IPC remains read-only;
- installed Windows service reports `mode=observe_recommend`;
- native service reports `dns_etw=true`;
- `pid_scoped_dns=true`;
- `mitm_https=false`;
- `auto_block=false`.

## Deferred work
- exact browser-origin attribution beyond DNS/process correlation;
- browser companion/extension;
- DNS policy enforcement and safe domain-level blocking strategy;
- WFP telemetry/enforcement research;
- Safe Banking isolated/protected session;
- mature anti-scam reputation/feed pipeline.
