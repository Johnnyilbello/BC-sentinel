# BC Sentinel Roadmap — v0.9.0-rc.1

Frozen line: **v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening**.

- v0.9.0-beta.1: Antispyware & persistence detection foundation.
- v0.9.0-beta.2: Reversible persistence remediation & PUP/Adware response.
- v0.9.0-beta.3: Advanced antimalware, PowerShell/script/LOLBin and fileless correlation.
- v0.9.0-rc.1: regression freeze, false-positive hardening, native Windows aggregate acceptance and live-service release gate.

## Exit criteria for v0.9 — completed

- full Python regression suite green: **482/482 PASS**;
- cross-platform v0.8/v0.9 acceptance gates green;
- benign dual-use/admin matrix stays below HIGH while strong malicious chains remain detectable;
- native Windows aggregate acceptance passes with zero critical failures;
- live Protection Service acceptance passes;
- upgrade/repair acceptance remains green;
- post-reboot live acceptance remains green;
- service-hardening benchmark passes.

The roadmap now proceeds to **v0.10.0-beta.1 — Web Protection / Anti-Phishing / Anti-Scam Mature Expansion Foundation**, followed by EDR, sandbox, IDS/IPS, privacy and identity modules.
