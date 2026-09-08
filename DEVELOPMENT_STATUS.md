# BC Sentinel — Development Status

## Current line

**v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation**

Status: **implementation branch active / checkpoint-4 rebase and full-source validation pending**.

The current source-of-record baseline remains the 2026-09-08 v0.9.0-rc.1 security checkpoint 4: **578 tests passed, zero skipped**, fresh Protection Service/UAC Broker builds, artifact integrity and local RC acceptance passed. Authenticode filename command injection is corrected and the native Authenticode sub-gate passes.

The v0.9 native elevated ETW/live Protection Service/UAC/upgrade/repair/reboot gates are deliberately **DEFERRED / OPEN** while v0.10 development proceeds. v0.9.0-rc.1 is therefore **not frozen and not production accepted**. Older repository statements claiming a 482/491-test frozen/native-accepted RC1 are superseded by checkpoint 4 and must not be used as release evidence.

BC Sentinel is not production-ready and should not replace Microsoft Defender or the native Windows security stack during development testing.

## Accepted baseline retained

- v0.8.0-rc.1 — **NATIVE WINDOWS ACCEPTED**
- v0.9.0-beta.1 — **NATIVE WINDOWS ACCEPTED**
- v0.9.0-beta.2 — **NATIVE WINDOWS ACCEPTED**
- v0.8 threat-intelligence/update-channel and v0.9 antispyware/remediation invariants remain mandatory regression requirements.
- checkpoint-3 updater hardening, checkpoint-4 Authenticode invocation hardening, quarantine and YARA regressions must remain intact when the v0.10 delta is rebased onto the complete source tree.

## v0.10.0-beta.1 scope

Beta1 extends the existing v0.7.2 Web Protection architecture rather than replacing it.

Implemented in the v0.10 delta:

- pure local/offline URL and domain reputation assessment;
- IDN/Punycode and mixed-script evidence;
- protected-identity look-alike context;
- bounded edit-distance-one typosquatting detection;
- brand token outside canonical domain evidence;
- explicit separation of declared identity, observed domain and canonical identity;
- userinfo/raw-IP/deep-subdomain/hostname-obfuscation context;
- bounded redirect-chain analysis including canonical-brand → look-alike transitions and raw-IP destinations;
- conservative credential/payment/prize/support/delivery scam-lure context that scores only when independent structural risk already exists;
- deterministic `WDR-*` heuristic fingerprint for stable deduplication evidence;
- false-positive fixtures for Microsoft, Google, GitHub, common CDN, Cloudflare, Salesforce and Atlassian endpoints;
- signed IOC precedence, exact-domain trust and signed-IOC-over-trust regression requirements;
- existing browser/DNS/network/download/execution correlation remains the authoritative chain and download origin must never override the independent file verdict.

## Safety invariants

- heuristic-only score hard cap: **49**;
- heuristic-only HIGH/CRITICAL qualification: disabled;
- heuristic auto-block: disabled;
- heuristic quarantine/delete/process-kill/persistence mutation: disabled;
- HTTPS MITM/root CA/TLS proxy/decryption: disabled;
- lure vocabulary alone does not score;
- exact-domain trust never becomes wildcard trust;
- active signed IOC evidence remains authoritative over older local trust;
- shared-IP/CDN safety rules from v0.7.2 remain frozen regression requirements;
- no mandatory cloud or external runtime service.

## Verification status

The connected GitHub repository is a security-relevant **delta repository**, not the complete checkpoint-4 source tree. The older v0.10 archive available in the file library predates checkpoint 4 and must not be used as the new base because doing so would lose later updater/AuthentiCode hardening.

Therefore the **578-pass checkpoint is baseline evidence only, not proof that this v0.10 delta passes 578+ tests**. The new Beta1 must remain unaccepted until this delta is applied to the complete checkpoint-4 tree and the following are rerun successfully:

1. targeted v0.10 web-reputation/phishing tests;
2. all existing v0.3.1→v0.9 regressions (expected floor: 578 tests, with any new tests added on top);
3. Python compileall;
4. `tools.v010_web_deception_acceptance` / v0.10 foundation gate;
5. fresh service/broker build and artifact integrity;
6. live v0.10 service gate when a native Windows validation run is performed.

Do **not** mark v0.10.0-beta.1 accepted and do **not** rewrite the deferred v0.9 native gates as PASS until there is corresponding evidence.