# BC Sentinel v0.10.0-beta.1 — Web Deception & Anti-Scam Foundation

First milestone of the mature Web Protection / Anti-Phishing / Anti-Scam expansion.

## Added

- explainable Web heuristic profile `v0.10.0-beta.1`;
- mixed Latin/Cyrillic/Greek hostname detection as bounded identity-deception evidence;
- IDN/Punycode, deep-subdomain, long-host and hyphen-density evidence consolidated into explicit signal codes/families;
- raw-IP URL and userinfo-before-host evidence;
- dense percent-encoding and nested HTTP/HTTPS redirect-parameter context;
- credential/account, payment/refund and prize/investment lure context only when independent structural risk is already present;
- `risk_families`, `signal_codes` and detailed heuristic provenance in `WebAssessment`;
- Protection Service status flags for the v0.10 deception profile and heuristic safety cap;
- dedicated `tools.v010_web_deception_acceptance` gate;
- foundation/live Windows acceptance gates for the new profile.

## False-positive policy

Words such as `login`, `invoice`, `refund`, `wallet`, `verify` and similar are not suspicious by themselves. They contribute only when structural/obfuscation risk has already been observed.

Heuristic-only outcomes are hard-capped at **49**, cannot qualify HIGH, cannot recommend containment and cannot trigger destructive response.

## Preserved precedence

- active signed domain/network IOC evidence remains authoritative;
- exact local domain trust remains bounded and revocable;
- signed IOC evidence can override older local trust under the existing v0.7 policy;
- no HTTPS MITM, injected root CA, local TLS proxy or traffic decryption.

## Frozen regression baseline

Every v0.10 acceptance run must retain the accepted v0.9.0-rc.1 regression gate. The target-Windows RC1 baseline was frozen with 482/482 Python tests and all native foundation/build/upgrade/live/repair/hardening/post-reboot gates passing.
