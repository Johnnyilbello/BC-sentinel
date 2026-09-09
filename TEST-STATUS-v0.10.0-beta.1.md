# BC Sentinel v0.10.0-beta.1 — Test Status

Status: **LOCAL RECONSTRUCTED REGRESSION GREEN; WINDOWS NATIVE FIX2 VALIDATION PENDING**.

Current FIX2 development evidence:

- complete reconstructed regression: **519 passed, 2 skipped, 0 failed**;
- skipped tests are Windows-native gates in the non-Windows development environment;
- targeted Authenticode + v0.10 regression: **32 passed, 1 native-Windows skip**;
- Python `compileall`: **PASS**;
- `tools.v010_web_deception_acceptance`: **PASS (`passed=true`)**;
- WinVerifyTrust is authoritative for Authenticode trust validity;
- PowerShell is best-effort certificate metadata only and cannot upgrade native trust.

The earlier Windows runs are superseded for FIX2 validation:

- initial package: 517 passed / 1 Authenticode native failure;
- FIX1: 518 passed / 1 Authenticode native failure;
- FIX2 requires a fresh target-Windows run before this native gate is closed.

The historical checkpoint-4 source was reconstructed from the last complete RC1 plus preserved checkpoint-3/4 hardening evidence; this package is not claimed to be byte-identical to the unavailable original checkpoint-4 source tree.
