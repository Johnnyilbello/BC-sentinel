# BC Sentinel v0.10.0-beta.3 — Clone Site & Scam/Fraud Detection Expansion

## Scope
Beta3 extends the local Web Protection foundation with explainable page-context analysis for clone-site and scam/fraud candidates while preserving the Beta1/Beta2 safety model.

### New local signals
- declared protected identity on a non-canonical domain;
- protected brand claims in page title/visible text outside canonical domains;
- credential forms on non-canonical brand pages;
- sensitive forms posting to a different host;
- bounded external-link fan-out only when an independent brand mismatch exists;
- irreversible-payment requests combined with structural risk;
- urgent payment pressure combined with structural risk;
- remote-support sensitive requests combined with structural risk;
- investment/crypto claims combined with structural risk;
- delivery/customs payment pressure combined with structural risk.

### Safety invariants
- heuristic cap remains 49;
- page text alone never creates a web block;
- no heuristic-only automatic block;
- no MITM, TLS interception, root CA, browser injection or mandatory cloud;
- signed IOC precedence and Beta2 reversible response policy are unchanged;
- generic commerce/payment language without structural risk remains unscored.

## Test orchestration policy
From Beta3 onward, both one-command launchers include upgrade/repair and the standard-user -> UAC broker gate. Reboot is the only intentionally deferred gate and will be exercised at the end of the roadmap.

- `TEST-V010-BETA3-ALL-NORMAL.bat`: full normal suite, local acceptances, auto-elevated admin phase, real upgrade/repair, live service gates, then standard-user -> UAC from the original non-elevated process.
- `TEST-V010-BETA3-ALL-ADMIN.bat`: full suite + admin phase + real upgrade/repair, then a Scheduled Task helper running with `Interactive` + `RunLevel Limited` exercises the true standard-user -> UAC gate.

## Local pre-delivery evidence
- full pytest: 543 passed, 2 Windows-native skipped, 0 failed;
- Beta1 local acceptance: PASS;
- Beta2 local acceptance: PASS;
- Beta3 clone/scam local acceptance: PASS;
- legacy Web Response regression: PASS;
- compileall: PASS.

## Final Windows evidence — 2026-09-08
- full Windows pytest: **545 passed, 0 failed**;
- admin targeted phase: **115 passed, 0 failed**;
- fresh Protection Service/UAC Broker builds: PASS;
- anti-downgrade same-version rejection: PASS;
- real same-version repair: PASS;
- Beta1/Beta2/Beta3 service-live acceptance: PASS;
- Windows native acceptance: PASS with zero critical failures;
- service hardening benchmark: PASS;
- standard-user -> UAC: **PASS** with `is_admin=false`;
- broker accounting after the gate: issued=1, consumed=1, completed=1, rejected=0, pending=0;
- final service health `HEALTHY` and hardening `ok=true`.

## Acceptance harness FIX2
The earlier COM and Explorer-token launcher attempts were host-dependent. FIX2 delegates standard-user process creation to Windows Task Scheduler using a temporary task with `LogonType Interactive` and `RunLevel Limited`. The child still fails closed unless it observes `is_admin=false`, and the task is removed afterward. This changes only the test harness, not the product security policy.

## Status
**v0.10.0-beta.3 is closed as the accepted development baseline.** Reboot persistence/recovery remains intentionally deferred until the final roadmap acceptance.