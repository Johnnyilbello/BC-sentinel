# BC Sentinel v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation

## Release line

Development beta. **Local reconstructed-tree validation green / native Windows acceptance pending / not production-ready.**

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

A complete v0.10 test candidate has now been reconstructed from the latest complete RC1 archive available to this workspace, with the documented checkpoint-3/checkpoint-4 hardening invariants re-applied before the v0.10 delta. This reconstruction is **not byte-identical** to the historical checkpoint-4 artifact, so the historical 578-test result is retained only as baseline evidence. Native Windows acceptance for this reconstructed candidate remains pending.

## Reconstructed full-tree validation

- full local regression: **516 passed, 2 Windows-native skips, 0 failed**;
- v0.10 targeted tests: **25 passed**;
- compileall: **PASS**;
- v0.10 local acceptance: **PASS**.

See `RECONSTRUCTION-NOTE-v0.10.0-beta.1.md`. Native Windows live/UAC/upgrade/repair/reboot gates remain open.

### Validation FIX1 — native Authenticode portability

After a Windows field run isolated one native Authenticode error, the signature-inspection subprocess was hardened to emit a fixed Base64 protocol instead of depending on Microsoft.PowerShell.Utility/ConvertTo-Json. The security properties from checkpoint 4 remain: filename is data, native PowerShell is pinned, Security module is loaded by literal OS path, failures are fail-closed, and execution policy is not relaxed.


## Authenticode FIX2 — 2026-09-08

Windows field testing exposed a second compatibility failure in the certificate-metadata PowerShell subprocess while verifying `kernel32.dll`. FIX2 moves authoritative signature validity to native Windows `WinVerifyTrust` and leaves PowerShell as best-effort metadata only. Native non-valid results remain fail-closed; metadata failure cannot upgrade trust or create publisher trust. Local reconstructed regression: 519 passed, 2 native-Windows skips, 0 failed; compileall and local v0.10 acceptance pass. Target-Windows FIX2 validation is still required.
