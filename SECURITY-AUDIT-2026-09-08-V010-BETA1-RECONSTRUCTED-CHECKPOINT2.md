# BC Sentinel v0.10.0-beta.1 — reconstructed full-tree checkpoint 2

Date: 8 September 2026

## Scope and provenance

This candidate was reconstructed from the latest complete v0.9.0-rc.1 source archive available to the workspace. The connected GitHub repository contains development deltas/snapshots but not the complete historical checkpoint-4 source tree. The reconstruction therefore reapplies the documented checkpoint-3 updater and checkpoint-4 Authenticode security invariants before integrating the current v0.10.0-beta.1 Web Reputation / Phishing delta.

This tree is **not represented as byte-identical** to the historical checkpoint-4 artifact. Historical checkpoint-4 evidence remains baseline evidence only; this candidate has its own validation record.

## Reconstructed checkpoint-3 updater hardening

- transaction source/target/backup/staging roots must be disjoint and non-root;
- approval is bound to source identity and authenticated source manifest;
- approved source files are read through pinned handles and revalidated;
- a process-held transaction lock serializes update operations;
- staging and previous deployment use sibling promotion/rename semantics;
- failed promotion restores the previous deployment;
- Windows staging ACL inherits the protected installed-tree posture;
- schema-2 HMAC-authenticated journals bind immutable transaction paths and manifests;
- unique temporary journal writes retry only bounded sharing/access errors;
- rollback verifies authenticated backup identity and rejects modified/rehashed backups;
- stale rollback over an unrelated release is rejected;
- rollback/recovery are idempotent;
- legacy schema-1 journals are refused for automatic rollback.

## Reconstructed checkpoint-4 Authenticode hardening

- untrusted filenames never enter PowerShell syntax;
- paths are transported as encoded data and decoded into variables;
- PowerShell is resolved through the native Windows system directory rather than PATH;
- Security and Utility modules are loaded explicitly from the native PowerShell tree;
- module auto-loading is disabled;
- child environment roots are normalized;
- the fixed inspection script is passed as an encoded command;
- no execution-policy bypass is introduced;
- module/subprocess/JSON failures fail closed with bounded diagnostics.

## v0.10 Beta1 security invariants

- pure local/offline URL/domain reputation;
- IDN/Punycode, mixed-script, Unicode confusable and typosquat evidence;
- declared identity separated from observed/canonical domain identity;
- raw-IP, userinfo, deep-subdomain and bounded redirect context;
- phishing/scam lure signals require independent structural risk;
- stable `WDR-*` heuristic fingerprint;
- deterministic precedence: active signed IOC > exact local trust > heuristics;
- heuristic score cap 49;
- no heuristic-only HIGH/CRITICAL or automatic blocking/destructive response;
- no HTTPS MITM/root CA/TLS decryption;
- no mandatory cloud dependency;
- shared-IP/CDN and independent downloaded-file verdict protections remain preserved.

## Local validation of this reconstructed tree

| Check | Result |
|---|---|
| v0.10 targeted suite | **25 passed** |
| Reconstructed checkpoint-3 updater regressions | **6 passed** |
| Reconstructed checkpoint-4 Authenticode regressions | **4 passed, 1 Windows-native skip** |
| Complete local pytest regression | **516 passed, 2 skipped, 0 failed** |
| Python compileall (`app sentinel tools tests`) | **PASS** |
| `tools.v010_web_deception_acceptance` | **PASS (`passed=true`)** |
| v0.9 RC1 local regression inside v0.10 acceptance | **PASS** |

The two skips are native-Windows-only checks: Authenticode inspection of a genuinely signed system binary and Windows PowerShell parser acceptance.

## Open native gates

This local checkpoint does **not** certify the reconstructed candidate for production. The user's Windows run must still establish current-build native/live/service evidence. Standard-user UAC, upgrade, repair and reboot gates remain open until separately exercised and recorded. Microsoft Defender and the native Windows security stack should remain enabled while testing.
