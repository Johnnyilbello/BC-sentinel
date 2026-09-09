# BC Sentinel v0.10.0-beta.1 — Authenticode FIX2

## Windows field failure addressed
The FIX1 Windows run reached 518 passing tests and one failure: native Authenticode inspection of `kernel32.dll` returned `UnknownError` because the certificate-metadata PowerShell subprocess emitted CLIXML error output before the BCS protocol record.

## Security correction
FIX2 separates **trust validity** from **certificate metadata**:

- `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` is now the authoritative local signature-validity gate.
- The file path is passed directly to the Windows API as data; no shell parsing is involved.
- UI is disabled for verification.
- revocation network access is disabled (`WTD_REVOCATION_CHECK_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL`).
- common no-signature results map to `NotSigned`.
- every other non-zero trust result fails closed as `UnknownError`.
- hardened PowerShell remains only a best-effort certificate metadata source after native `Valid`.
- PowerShell metadata failure cannot downgrade native `Valid`; publisher stays blank, so publisher allowlisting cannot accidentally succeed.
- PowerShell metadata can never upgrade a native non-valid result.

No execution-policy relaxation, TLS interception, cloud lookup, automatic destructive action, or trust broadening is introduced.

## Development validation
- targeted Authenticode + v0.10 tests: **32 passed, 1 native-Windows skip**
- complete reconstructed regression: **519 passed, 2 native-Windows skips, 0 failed**
- `compileall`: **PASS**
- v0.10 local acceptance: **PASS (`passed=true`)**

The Windows-native Authenticode gate remains pending until the FIX2 package is run on the target Windows host.
