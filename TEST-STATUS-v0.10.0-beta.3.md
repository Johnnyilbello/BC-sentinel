# Test Status — v0.10.0-beta.3

Status: **ACCEPTED DEVELOPMENT BASELINE on Windows; reboot intentionally deferred**.

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

## Final Windows acceptance evidence — 2026-09-08
- full Windows pytest: **545 passed, 0 failed**;
- admin targeted phase: **115 passed, 0 failed**;
- Protection Service + UAC Broker fresh builds: PASS;
- same-version upgrade attempt correctly rejected as `same_version_upgrade_rejected` (anti-downgrade invariant): PASS;
- real same-version repair: PASS;
- Beta1/Beta2/Beta3 service-live acceptance: PASS;
- Windows native acceptance: PASS with zero critical failures;
- service hardening benchmark: PASS;
- final standard-user -> UAC retest with FIX2: **PASS**;
- helper identity: `is_admin=false`;
- direct privileged request from standard user: `admin_required` as expected;
- one-action UAC broker: issued=1, consumed=1, completed=1, rejected=0, pending=0;
- post-broker service health: `HEALTHY`;
- post-broker hardening: `ok=true`, sealed, HMAC/ACL/SCM/audit checks green.

## UAC harness closure
The original COM path remained elevated on this host. FIX1 using `CreateProcessWithTokenW` was not reliable. FIX2 uses a temporary Windows Scheduled Task with `LogonType Interactive` and `RunLevel Limited`; the child independently verifies `is_admin=false` before the UAC broker acceptance can pass, and the temporary task is removed afterward.

This is a test-harness correction only. No protection policy was weakened.

## Remaining deferred gate
- reboot persistence/recovery: **DEFERRED by roadmap decision until final roadmap acceptance**.

No other Beta3 acceptance gate remains open.