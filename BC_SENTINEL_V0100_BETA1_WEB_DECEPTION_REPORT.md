# BC Sentinel v0.10.0-beta.1 — Web Deception & Anti-Scam Report

## Goal

Mature the existing Web Protection engine without introducing HTTPS interception or heuristic auto-blocking. The new layer focuses on explainable deception context that can support operator review and later incident correlation.

## Evidence families

- `identity_deception`: IDN/Punycode and mixed-script hostnames;
- `host_structure`: raw-IP URLs, deep subdomain chains, long or hyphen-dense hostnames;
- `url_deception`: userinfo/credentials before the host;
- `url_obfuscation`: dense percent encoding;
- `redirect_context`: nested HTTP/HTTPS destinations in query parameters;
- `scam_lure`: account/credential, payment/refund and prize/investment wording only after independent structural risk exists.

## Safety model

- lure vocabulary alone scores zero;
- all local heuristic evidence is capped at 49;
- heuristic evidence cannot independently qualify HIGH;
- heuristic evidence cannot create containment recommendations;
- active signed IOC evidence retains deterministic malicious precedence;
- exact local trust is not broadened to wildcard trust;
- no HTTPS MITM or root-certificate installation.

## Regression model

`tools.v010_web_deception_acceptance` invokes the frozen v0.9 RC1 acceptance first, then validates safe-lure cases, mixed-script deception, raw-IP lure context, nested redirects, signed IOC precedence and exact-domain trust precedence.
