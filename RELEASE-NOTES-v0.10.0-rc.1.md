# BC Sentinel v0.10.0-rc.1 — Web Protection Consolidation

## Purpose
RC1 freezes the v0.10 Beta1→Beta3 web-security behavior before moving to v0.11 EDR. It adds consolidation, compatibility and performance acceptance rather than broadening automatic response.

## Frozen v0.10 profiles
- Beta1 deception/reputation: `v0.10.0-beta.1`;
- Beta2 reversible response: `v0.10.0-beta.2`;
- Beta3 clone/scam page context: `v0.10.0-beta.3`;
- product release candidate: `0.10.0-rc.1`.

## RC1 additions
- `tools.v010_rc1_acceptance` consolidation gate;
- 323-case benign/enterprise compatibility matrix;
- local assessment throughput + p95 latency gate;
- service-live assessment IPC latency gate;
- `tests/test_v010_rc1_consolidation.py`;
- one-command RC1 normal/admin launchers;
- retained real upgrade, same-version repair and standard-user -> UAC acceptance;
- reboot still deferred to final roadmap acceptance.

## Safety invariants unchanged
- heuristic score cap remains 49;
- no heuristic-only HIGH/CRITICAL;
- no heuristic automatic blocking;
- no page-text-only blocking;
- no HTTPS MITM/root CA/TLS interception;
- signed IOC precedence remains authoritative;
- exact trust cannot override active signed IOC;
- shared-IP/CDN guard remains fail-closed;
- no mandatory cloud dependency.

## Local pre-delivery evidence
- full pytest: **547 passed, 2 Windows-native skips, 0 failed**;
- targeted Beta2/Beta3/RC1: **28 passed**;
- compileall: PASS;
- Beta1/Beta2/Beta3 local acceptances: PASS;
- RC1 consolidation local acceptance: PASS;
- compatibility: **323 checked, 0 failures**;
- local assessment performance: PASS.

Native Windows/live, upgrade, repair and standard-user -> UAC RC1 evidence must be produced on the Windows host by the packaged master launcher. Reboot is deliberately not part of RC1 acceptance.
