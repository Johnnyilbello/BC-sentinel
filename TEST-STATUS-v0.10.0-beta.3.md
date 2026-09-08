# Test Status — v0.10.0-beta.3

Status: **candidate ready for Windows acceptance; not final-accepted yet**.

## Local pre-delivery
- 543 passed
- 2 skipped (Windows-native only in the non-Windows build environment)
- 0 failed
- compileall PASS
- Beta1 Web Deception local acceptance PASS
- Beta2 Reversible Web Response local acceptance PASS
- Beta3 Clone Site / Scam-Fraud local acceptance PASS
- legacy Web Threat Response regression PASS

## Mandatory Windows acceptance policy from Beta3 onward
Both supported master launchers include all gates except reboot:
1. full regression;
2. targeted native/security tests;
3. build Protection Service + UAC Broker;
4. real upgrade when an older installed build is present, with anti-downgrade validation;
5. real same-version repair;
6. Beta1/Beta2/Beta3 service-live acceptance;
7. Windows live acceptance and service benchmark;
8. true standard-user -> UAC one-action broker acceptance.

Reboot persistence/recovery is intentionally deferred to the final roadmap acceptance and must not be marked PASS before then.

## Windows acceptance evidence — 2026-09-08 before UAC harness FIX1
- full Windows pytest: **545 passed, 0 failed**;
- admin targeted phase: **115 passed, 0 failed**;
- Protection Service + UAC Broker fresh builds: PASS;
- same-version upgrade attempt: correctly rejected as `same_version_upgrade_rejected` (anti-downgrade invariant);
- real same-version repair: PASS;
- Beta1/Beta2/Beta3 service-live acceptance: PASS;
- Windows native acceptance: PASS with zero critical failures;
- service hardening benchmark: PASS;
- standard-user -> UAC from ADMIN launcher: harness failure because COM launch remained elevated (`is_admin=true`).

FIX1 changes only this de-elevation harness. The product engine and already-green acceptance results are unchanged. The final UAC gate remains pending until `RETEST-V010-BETA3-STANDARD-UAC-ADMIN.bat` returns PASS.
