# BC Sentinel v0.10.0-beta.1 — Native Authenticode FIX1

Date: 2026-09-08

## Windows field failure addressed

The reconstructed v0.10 package passed 517 tests on the target Windows host and exposed one native-only Authenticode failure: inspection of `kernel32.dll` returned `UnknownError` with serialized PowerShell error output instead of `Valid`.

## Fix

- retained native `GetSystemDirectoryW` resolution for Windows PowerShell;
- retained filename-as-data Base64 encoding and `-EncodedCommand` injection hardening;
- retained explicit literal-path loading of `Microsoft.PowerShell.Security`;
- removed the Authenticode subprocess dependency on `Microsoft.PowerShell.Utility` and `ConvertTo-Json`;
- introduced a fixed `BCS-AUTH1` Base64 field protocol parsed fail-closed in Python;
- retained no execution-policy relaxation and no PATH-based PowerShell selection;
- added protocol round-trip and malformed-protocol regressions.

## Local validation after fix

- Authenticode targeted: 5 passed, 1 native-Windows-only skipped in this environment.
- Full regression: 517 passed, 2 native/platform skips, 0 failed.
- `compileall`: PASS.
- `tools.v010_web_deception_acceptance`: `passed=true`.

## Required Windows validation

Re-run `TEST-V010-NORMAL.ps1`. The native gate must report `kernel32.dll` as `Valid`; it is not waived or downgraded.
