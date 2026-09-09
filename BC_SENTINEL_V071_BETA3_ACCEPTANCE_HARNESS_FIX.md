# BC Sentinel v0.7.1-beta.3 Acceptance Harness Fix

## Issue
On native Windows, the unit test `test_beta3_safe_ioc_acceptance_passes_locally` invoked the IOC acceptance runner in its live-service mode. A standard/non-elevated pytest run therefore returned `administrator_required` and caused a false-negative test failure even though signature verification and tamper rejection were correct.

## Fix
- `tools.ioc_acceptance.run()` now accepts `native_service: bool = True`.
- Side-effect-free unit tests call `run(native_service=False)` and validate only cryptographic fixture verification/tamper rejection.
- The CLI keeps the default `native_service=True`, so `python -m tools.ioc_acceptance` still performs the real elevated Windows service/import acceptance exactly as intended.
- No firewall, IOC verification, containment, updater, Protection Service or GUI security semantics were weakened.

## Expected native Windows result
- Standard PowerShell full pytest: **350 passed**.
- Elevated standalone `tools.ioc_acceptance`: performs the native service/import checks.
