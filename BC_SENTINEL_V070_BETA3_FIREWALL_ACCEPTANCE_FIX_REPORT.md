# BC Sentinel v0.7.0-beta.3 — Native Firewall Acceptance Fix Report

## Root cause

Beta 2 correctly created and enumerated the Windows Firewall rule, but the final acceptance predicate compared the observed `remote_address` to the probe address with raw string equality. Windows exposed the same IPv4 host as a host-plus-dotted-netmask representation, producing a false negative after successful enforcement.

## Remediation

`tools/firewall_acceptance.py` now performs semantic network comparison via Python `ipaddress`. It accepts equivalent host/CIDR/dotted-netmask representations while refusing unparsable or multi-address expressions for this single-endpoint acceptance probe. The final predicate additionally checks logical rule id, exact managed group, direction, protocol, port/application scope and enabled state.

## Update semantics

The release is versioned `0.7.0-beta.3`. This intentionally makes the user's installed Beta 2 a valid upgrade source/target pair. Anti-downgrade is unchanged: same-version or older targets do not pass Upgrade. Repair remains the only accepted same-version mode.

## Regression coverage

- IPv4 host == `/32`.
- IPv4 host == dotted `/255.255.255.255`.
- IPv4 CIDR == equivalent dotted netmask.
- IPv6 host == `/128`.
- wrong endpoint does not match.
- wrong group/direction does not match.
- Beta 3 is accepted as an Upgrade from Beta 2.
- same-version Upgrade is rejected.
- same-version Repair is accepted.
- older Upgrade remains rejected.

## Verification

Development suite: `302 passed, 1 skipped`; compileall PASS. Native Windows remains the release gate for the COM round-trip behavior.
