# BC Sentinel Roadmap — v0.10.0-beta.3

## Completed development lines
- v0.10.0-beta.1: local Web Reputation, IDN/Punycode, lookalike/typosquat, redirect and conservative phishing/scam context.
- v0.10.0-beta.2: operator-approved reversible Web Response with signed IOC revalidation, same-PID DNS/network qualification, shared-IP/CDN guard, TTL, deduplication, rollback and restart recovery.
- v0.10.0-beta.3: clone-site and scam/fraud page-context expansion with sensitive form destination analysis and multi-signal anti-fraud heuristics.

## Acceptance policy
From Beta3 onward every normal/admin master launcher must include upgrade/repair and the real standard-user -> UAC broker gate. Only reboot remains deferred until final roadmap acceptance.

## Next planned milestone
**v0.10.0-rc.1 — Web Protection consolidation & adversarial hardening**
- merge Beta1/Beta2/Beta3 evidence into one deterministic Web Protection decision envelope;
- broaden false-positive corpus for Microsoft/Google/GitHub/CDNs/e-commerce/SaaS;
- stress malformed URLs, Unicode, redirect chains and page-context payload limits;
- persistence/cleanup audit for reversible web rules;
- service/live acceptance, upgrade/repair and standard-user UAC mandatory in both master launchers;
- no reboot gate until final roadmap closure.

After v0.10 RC, proceed to v0.11 EDR.
