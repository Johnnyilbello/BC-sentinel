# Security checkpoint — v0.10.0-beta.1 / checkpoint 1 — 8 September 2026

## Scope and source-of-record

This checkpoint starts **v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation** while preserving the latest documented v0.9.0-rc.1 checkpoint-4 baseline.

The source-of-record baseline before the v0.10 delta is:

- 578 Python tests passed, zero skipped;
- fresh Protection Service and UAC Broker builds passed;
- local RC acceptance passed;
- frozen isolated-pipe self-test passed;
- Python compileall passed;
- 169-file artifact integrity passed;
- Authenticode filename command injection corrected;
- native Authenticode foundation sub-gate passed.

The v0.9 elevated current-build/live/UAC/upgrade/repair/reboot gates remain **DEFERRED / OPEN**. This checkpoint does not reinterpret them as PASS and does not claim that v0.9 is frozen or production accepted.

## Repository reconciliation finding

The pre-existing `v0.10.0-beta.1` GitHub branch was based on older evidence and described v0.9 as frozen/native accepted with 482/491-test-era results. That statement conflicts with the later checkpoint-4 evidence and is superseded.

The connected GitHub repository contains a security-relevant source/delta set rather than the complete checkpoint-4 source tree. The older v0.10 ZIP available in the file library also predates checkpoint 4. It is intentionally **not** being promoted as the current base, because replacing checkpoint 4 with that archive could discard later updater and Authenticode hardening.

## v0.10 Beta1 security delta

### Local reputation and phishing primitives

`sentinel/web_deception.py` now provides a pure local/offline assessment layer with:

- IDN/Punycode evidence;
- mixed Latin/Cyrillic/Greek script evidence;
- bounded confusable-skeleton comparison for common cross-script impersonation glyphs;
- bounded edit-distance-one typosquatting evidence;
- protected identity token outside canonical-domain evidence;
- explicit `declared_identity` vs `observed_host` vs `canonical_identity` context;
- raw-IP URL and URL-userinfo evidence;
- deep-subdomain, long-host and hyphen-density structure evidence;
- nested URL/redirect context;
- bounded redirect-chain analysis, including canonical-brand → look-alike and raw-IP transitions;
- scam-lure families for credential, payment/refund, prize/investment, support/remote-access and delivery/customs contexts;
- lure scoring only when independent structural risk already exists;
- stable deterministic `WDR-*` heuristic fingerprints for deduplication support.

No network lookup is performed by this pure layer. It is not a cloud reputation service and cannot create a deterministic malware verdict.

### Decision boundaries

The v0.10 delta preserves the existing Web Protection authority order:

1. active signed IOC evidence;
2. exact-domain local trust;
3. local bounded heuristics.

A signed IOC remains able to override older exact-domain trust. Heuristic-only evidence is capped at 49 and cannot produce HIGH/CRITICAL, containment recommendation, quarantine, delete, process kill or persistence mutation.

### Existing web/download chain preserved

v0.10 reuses rather than duplicates the accepted v0.7.2 architecture:

`browser/process → PID-scoped DNS/domain → network connection → download record → independent file verdict → execution evidence → incident`

Shared-IP/CDN safeguards remain mandatory. Download origin remains provenance and must never override the independent file verdict or cause origin-driven automatic quarantine.

## New deterministic test coverage in the delta

A new pure-primitives test module covers:

- benign lure words;
- benign IDN/Punycode;
- mixed-script PayPal-like look-alike fixture;
- Microsoft-like edit-distance-one typosquat fixture;
- canonical subdomain vs brand-token subdomain abuse;
- explicit identity/domain separation;
- raw-IP + userinfo cap behavior;
- canonical-brand redirect to look-alike;
- redirect to raw IP;
- enterprise false-positive fixtures for Microsoft, Google, GitHub, common CDN, Cloudflare, Salesforce and Atlassian;
- stable/order-insensitive heuristic fingerprint;
- fixed Beta1 heuristic cap/profile.

The full-tree integration test delta additionally requires:

- signed malicious domain IOC precedence;
- exact-domain trust;
- signed IOC overriding older trust;
- Protection Service policy status (`mitm_https=false`, `auto_block=false`, cap 49);
- preservation of the download-origin/file-verdict separation;
- registered `web-reputation-v010-beta1-foundation` and `web-reputation-v010-beta1-live` gates.

## Adversarial review performed on the design

The following failure modes are explicitly bounded by the implementation/test contract:

- adding the word `login`, `invoice`, `refund`, `wallet`, `support` or `delivery` to a benign URL cannot score by itself;
- a benign IDN is contextual evidence but remains below review threshold by itself;
- one typo/look-alike signal cannot exceed the heuristic cap;
- a canonical brand-controlled domain is not flagged merely because a subdomain/path includes the brand name;
- `microsoft.com.evil.example` is not treated as a Microsoft canonical subdomain;
- a redirect chain cannot turn heuristic evidence into automatic blocking;
- local trust cannot suppress an active signed IOC;
- a userinfo/raw-IP combination remains capped and advisory;
- no heuristic signal can request destructive file/process/persistence action;
- no network/cloud dependency is required to evaluate the local heuristic layer.

## Verification status — IMPORTANT

**v0.10.0-beta.1 is NOT accepted by this checkpoint.**

The 578-pass result belongs to the v0.9 checkpoint-4 baseline *before* this v0.10 delta. It is not valid evidence that the new code passes 578+ tests.

The full checkpoint-4 source tree is not present in the connected GitHub repository or current attached artifacts, so this checkpoint cannot truthfully claim:

- full-suite PASS after applying the v0.10 delta;
- compileall PASS for the rebased complete tree;
- fresh service/broker builds after the delta;
- artifact-integrity PASS after the delta;
- native/live v0.10 gate PASS.

Required acceptance sequence when the complete checkpoint-4 tree is available:

1. apply/rebase this v0.10 delta onto that exact tree;
2. run the new pure and integration test modules;
3. run the complete regression suite — **no regression from the existing 578-test baseline**, with the new tests increasing the total;
4. run compileall;
5. run `tools.v010_web_deception_acceptance`;
6. run the v0.10 foundation Windows acceptance gate;
7. build fresh Protection Service and Broker artifacts and verify integrity;
8. run the v0.10 live gate when native Windows validation is intentionally resumed.

Any failure keeps Beta1 open. The deferred v0.9 native gates remain recorded separately and must not be silently converted into success evidence.
