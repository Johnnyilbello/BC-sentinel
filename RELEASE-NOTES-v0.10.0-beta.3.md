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

## Test orchestration change
From Beta3 onward, both one-command launchers include upgrade/repair and the standard-user -> UAC broker gate. Reboot is the only intentionally deferred gate and will be exercised at the end of the roadmap.

- `TEST-V010-BETA3-ALL-NORMAL.bat`: full normal suite, local acceptances, auto-elevated admin phase, real upgrade/repair, live service gates, then standard-user -> UAC from the original non-elevated process.
- `TEST-V010-BETA3-ALL-ADMIN.bat`: full suite + admin phase + real upgrade/repair, then a de-elevated helper attempts the real standard-user -> UAC gate and fails closed if it cannot obtain a medium-integrity process.

## Local pre-delivery evidence
- full pytest: 543 passed, 2 Windows-native skipped, 0 failed;
- Beta1 local acceptance: PASS;
- Beta2 local acceptance: PASS;
- Beta3 clone/scam local acceptance: PASS;
- legacy Web Response regression: PASS;
- compileall: PASS.

Windows evidence now confirms the full regression suite, native/admin phase, build, repair, Beta1/Beta2/Beta3 live acceptance and hardening. The only remaining Beta3 acceptance item is the standard-user -> UAC launcher gate; reboot remains deferred by roadmap decision.


## Harness FIX1
The ADMIN one-command launcher now starts its standard-user helper from the filtered Explorer token using `CreateProcessWithTokenW`, instead of relying on `Shell.Application`. The helper independently requires `is_admin=false` before the UAC broker test can pass. This is a test-harness correction only; no protection or response policy was relaxed.

## Acceptance harness FIX2
Sostituito il launcher Explorer-token/`CreateProcessWithTokenW` con un task temporaneo Windows `Interactive` + `RunLevel Limited`. Il child continua a verificare `is_admin=false` prima del broker, il task viene rimosso in `finally`, e il retest mirato crea autonomamente `.venv` quando necessario. Nessuna modifica al motore di protezione.
