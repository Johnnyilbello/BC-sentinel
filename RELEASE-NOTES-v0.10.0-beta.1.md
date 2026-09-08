# BC Sentinel v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation

## Release line

Development beta. **Not accepted / not production-ready.**

This milestone advances from the v0.9.0-rc.1 checkpoint-4 baseline while leaving the still-open v0.9 elevated/live/UAC/upgrade/repair/reboot gates explicitly deferred.

## Added

- Pure local/offline URL/domain reputation primitives.
- IDN/Punycode and mixed-script evidence.
- Bounded look-alike and edit-distance-one typosquatting detection.
- Brand-token evidence outside canonical domains.
- Explicit declared-identity / observed-domain / canonical-identity separation.
- Raw-IP, userinfo, deep-subdomain and URL-obfuscation context.
- Bounded redirect-chain analysis, including canonical-brand → look-alike and raw-IP transitions.
- Conservative scam/fraud lure context that scores only when independent structural risk exists.
- Stable `WDR-*` heuristic fingerprint for deterministic deduplication support.
- Enterprise false-positive fixtures for Microsoft, Google, GitHub, CDN, Cloudflare, Salesforce and Atlassian endpoints.
- Explicit signed-IOC-over-local-trust regression requirement.
- v0.10 foundation/live gate names: `web-reputation-v010-beta1-foundation` and `web-reputation-v010-beta1-live`.

## Preserved security boundaries

- heuristic score cap: 49;
- no heuristic-only HIGH/CRITICAL;
- no heuristic auto-block;
- no heuristic-driven quarantine/delete/process kill/persistence mutation;
- no HTTPS MITM/root CA/TLS proxy/decryption;
- no mandatory cloud/external runtime dependency;
- signed IOC > exact-domain trust > local heuristics;
- shared-IP/CDN protections remain mandatory;
- download origin never overrides the independent file verdict.

## Validation status

The latest documented pre-delta baseline is checkpoint 4: **578 passed, zero skipped**. The connected repository does not contain the complete checkpoint-4 source tree, and the older v0.10 archive predates those fixes. Therefore this Beta1 is **not accepted** until the delta is rebased onto the complete checkpoint-4 tree and targeted tests, full regressions, compileall, acceptance, fresh builds and integrity checks pass.
