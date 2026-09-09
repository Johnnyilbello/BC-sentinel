# BC Sentinel — Development Status

Current development candidate: **v0.10.0-rc.1 — Web Protection Consolidation**.

## Accepted v0.10 baseline entering RC1
- Beta1 Web Reputation / Anti-Phishing foundation: accepted regression baseline.
- Beta2 Reversible Web Response: accepted regression baseline.
- Beta3 Clone Site / Scam-Fraud expansion: accepted Windows development baseline on 2026-09-08.
- Final Beta3 Windows evidence: 545/545 full regression, 115/115 admin/security, fresh service/broker build, anti-downgrade, real repair, Beta1/Beta2/Beta3 service-live, Windows native acceptance, hardening benchmark and true standard-user -> UAC all PASS.
- Reboot is intentionally deferred until final roadmap acceptance.

## RC1 scope
- freeze Beta1→Beta3 behavior and safety invariants;
- high-volume benign/enterprise compatibility matrix;
- local page-assessment latency/throughput checks;
- native Windows/live service latency evidence;
- retain upgrade + repair + standard-user -> UAC in both one-command master launchers;
- no new heuristic auto-block, MITM or destructive behavior.

## Local RC1 verification
- full pytest: **547 passed, 2 Windows-native skipped, 0 failed**;
- targeted Beta2/Beta3/RC1: **28 passed**;
- compatibility matrix: **323 benign fixtures, 0 failures**;
- local page-assessment performance: PASS;
- compileall: PASS;
- Beta1/Beta2/Beta3 local acceptance: PASS;
- RC1 consolidation local acceptance: PASS.

## Windows acceptance contract
Run exactly one master command from normal PowerShell or one from Administrator PowerShell. Both include the complete regression suite, native/admin phase, real upgrade/repair and true standard-user -> UAC. Reboot remains the only excluded gate.
