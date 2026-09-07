# BC Sentinel Development Status

## Current

**v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation**

Status: **READY FOR NATIVE WINDOWS ACCEPTANCE**.

Verification on the exact extracted release tree during the repository update:

- pytest: **477 passed, 1 Windows-only skipped**;
- compileall: **PASS**;
- release SHA-256: `36d7fe86b8741567c67505b7ccb429915afe89d5bff5ac95b6f61d56e17c32eb`;
- no automatic process termination introduced by Beta3;
- no automatic file deletion/quarantine introduced by Beta3;
- no automatic persistence mutation introduced by Beta3.

The single skipped test is Windows-only. Beta3 is not marked as native-frozen by this update; the dedicated `antimalware-v090-beta3-*` gates and aggregate Windows acceptance remain the freeze requirement.

## Accepted baseline

- `v0.8.0-rc.1 — Consolidation & Release Hardening`: **NATIVE WINDOWS ACCEPTED**.
- `v0.9.0-beta.1 — Antispyware & Persistence Detection Foundation`: **NATIVE WINDOWS ACCEPTED**.
- `v0.9.0-beta.2 — Reversible Persistence Remediation & PUP/Adware Response`: **NATIVE WINDOWS ACCEPTED**.

The v0.7 firewall/Web Protection, v0.8 signed-threat/update-channel and v0.9 persistence/remediation safety invariants remain regression requirements.

## Beta3 scope

Beta3 adds advisory advanced-antimalware and fileless correlation for PowerShell, script hosts and Windows LOLBins. It correlates command context, parent/child relationships, short-lived same-PID process→network chains and qualified deterministic file/IOC evidence.

False-positive boundaries remain conservative:

- one dual-use executable is not malware by identity;
- one evidence family cannot independently qualify HIGH;
- stronger outcomes require converging independent evidence or qualified deterministic evidence;
- high-severity findings remain explainable and do not bypass existing protected response workflows.

## Next

After Beta3 native acceptance: `v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening`.
