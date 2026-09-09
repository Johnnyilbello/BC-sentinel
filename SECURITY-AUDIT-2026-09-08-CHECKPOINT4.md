# Local security checkpoint 4 — 8 September 2026

Continues checkpoint 3. **v0.9 is not frozen; the full roadmap remains open.**

## Authenticode command-injection reproduction

A real Windows filename containing a typographic quote could terminate the PowerShell literal used by signature inspection. In the isolated reproducer, the remainder of the filename created a zero-byte marker inside the test-owned temporary directory. `audit-20260908-checkpoint4/quote-before.txt` preserves the child output and `filename_executed_as_code: True`. No external target, payload, service mutation or privileged host action was used. The risk applies at the privilege of the scanning process; exploitation in a live SYSTEM service was not attempted on the host.

The filename is now encoded as data and decoded into a variable; it never enters PowerShell syntax. The entire fixed script is passed as an encoded command. The PowerShell executable is resolved through the native system-directory API, not PATH or environment roots. Security and Utility modules are explicitly loaded from the OS PowerShell directory, with module auto-loading disabled. Child-only environment roots are normalized. Import failures stop processing and retain diagnostic text; no execution policy was relaxed.

## Verified evidence

| Check | Result |
|---|---|
| Targeted reputation and invocation tests | 26 passed |
| Complete regression | **578 passed, zero skipped**, 111.60 seconds |
| Native Authenticode foundation sub-gate | Passed (`authenticode-native-gate.json`), signed Python binary identified correctly |
| Local RC acceptance | Passed (`acceptance-rc.json`) |
| Fresh service and broker builds | Passed |
| Frozen isolated pipe self-test | Passed |
| Python compileall | Passed |
| Artifact integrity | 169 files verified |

Eight additional regressions cover literal ASCII/typographic quote handling, poisoned executable/module/environment lookup, a genuinely signed OS binary and fail-closed diagnostic errors. Initial test failures from using invalid PE bytes as an unsigned-signature fixture were corrected by using harmless unsigned PowerShell text for the `NotSigned` expectation; the code-execution marker assertion remains intact.

Artifact: `audit-20260908-checkpoint4/BC-Sentinel-Protection-audit.zip`.
SHA-256: `193333cf412d626e5b1e6698977ac2aef8c21f03c0c186a10320214d07880d80`.
Source and artifact hashes: `build-evidence.json`.

This development build is not production signed or installed. Native elevated ETW/live/UAC/upgrade/repair/reboot gates still require the isolated Windows guest being prepared. The previous Authenticode environment failure is resolved by the native sub-gate; this does not turn the earlier aggregate failure into a pass. Other subprocess invocation sites and the development-only privileged bootstrap remain subjects for subsequent security review. Signature context is advisory and is not a guarantee that a file is safe.
