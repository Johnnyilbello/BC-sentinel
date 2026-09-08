# BC Sentinel — v0.10.0-beta.1 Roadmap Update

Current milestone: **Web Reputation & Phishing Detection Foundation**.

## Implemented in the development delta

- local/offline URL/domain assessment;
- IDN/Punycode + mixed-script evidence;
- look-alike/typosquatting context;
- declared identity vs observed/canonical domain separation;
- raw-IP/userinfo/deep-subdomain/obfuscation context;
- bounded redirect-chain analysis;
- scam/fraud lure context only after independent structural risk;
- stable `WDR-*` heuristic fingerprint;
- signed IOC > exact trust > heuristic precedence;
- deterministic false-positive fixtures;
- v0.10 foundation/live acceptance gate definitions.

## Unchanged safety model

No HTTPS MITM, root CA, TLS decryption, heuristic auto-block, heuristic HIGH/CRITICAL, automatic kill/delete/quarantine or mandatory cloud dependency. Shared-IP/CDN and independent download-file-verdict protections remain frozen regression requirements.

## Status

**NOT ACCEPTED.** The latest complete baseline is v0.9.0-rc.1 checkpoint 4 with 578 passed / zero skipped. The v0.10 GitHub branch is a delta and has not yet been rebased/tested on that complete tree. v0.9 elevated/live/UAC/upgrade/repair/reboot gates remain deferred/open.

## Next gate

Rebase onto checkpoint 4 → targeted v0.10 tests → complete 578+ regression → compileall → v0.10 local acceptance → fresh build/integrity → foundation gate. Live native validation remains a separate gate.