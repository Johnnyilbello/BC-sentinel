# TEST STATUS — BC Sentinel v0.10.0-beta.1

Status: **PENDING COMPLETE CHECKPOINT-4 REBASE / NOT ACCEPTED**.

## Source-of-record baseline before v0.10 delta

Checkpoint 4 on 8 September 2026:

- complete regression: **578 passed, zero skipped**;
- native Authenticode foundation sub-gate: PASS;
- local v0.9 RC acceptance: PASS;
- fresh Protection Service / UAC Broker builds: PASS;
- isolated pipe self-test: PASS;
- compileall: PASS;
- artifact integrity: 169 files verified.

These are pre-delta results and MUST NOT be presented as v0.10 test results.

## v0.10 tests added/expanded in the delta

- `tests/test_v010_beta1_web_reputation_primitives.py`
  - benign lure words;
  - benign IDN;
  - mixed-script/confusable identity;
  - typosquatting;
  - brand/subdomain abuse;
  - declared identity vs observed host;
  - raw-IP/userinfo cap;
  - redirect look-alike/raw-IP context;
  - enterprise false-positive matrix;
  - deterministic `WDR-*` fingerprint;
  - cap/profile invariants.

- `tests/test_v010_beta1_web_deception_anti_scam.py`
  - existing WebProtectionEngine integration;
  - deterministic signed IOC precedence;
  - exact-domain trust;
  - signed IOC overriding older exact-domain trust;
  - v0.10 service safety posture;
  - download-origin/file-verdict separation;
  - deferred v0.9 native-gate metadata;
  - v0.10 Windows acceptance gate registration.

## Required green gate

After applying the delta to the exact checkpoint-4 full source tree:

1. targeted v0.10 tests PASS;
2. full regression PASS with **no loss of any of the existing 578 tests** and no skips introduced to hide failures;
3. compileall PASS;
4. `python -m tools.v010_web_deception_acceptance` PASS;
5. fresh service/broker builds PASS;
6. artifact integrity PASS;
7. `web-reputation-v010-beta1-foundation` PASS;
8. live gate only when native Windows validation is resumed.

Until those results exist, no Beta1 acceptance count or release checksum is claimed.
