# BC Sentinel v0.9.0-beta.3 — Test Status

## Release identity

**Version:** `0.9.0-beta.3`  
**Release:** `BC_Sentinel_v0_9_0_Beta3_Advanced_Antimalware_Fileless_Correlation.zip`  
**SHA-256:** `36d7fe86b8741567c67505b7ccb429915afe89d5bff5ac95b6f61d56e17c32eb`

## Extracted-tree verification

Verification performed against the exact extracted release archive on 2026-09-07:

```text
python -m compileall -q app sentinel tools tests   PASS
python -m pytest -q                               477 passed, 1 skipped
```

The single skipped test is Windows-only. No cross-platform pytest failure was observed in the release tree.

## Beta3 safety invariants

The advanced-antimalware module remains advisory:

- a single PowerShell/script-host/LOLBin process is not malware by identity;
- one evidence family cannot independently qualify HIGH;
- no automatic process termination;
- no automatic file deletion;
- no automatic quarantine from this module alone;
- no automatic persistence mutation;
- read-only service status/findings surfaces remain separate from protected response workflows.

## Freeze status

**READY FOR NATIVE WINDOWS ACCEPTANCE — NOT YET FROZEN BY THIS VERIFICATION.**

Native Windows acceptance remains the release-freeze gate for `v0.9.0-beta.3`, including the dedicated `antimalware-v090-beta3-*` service/live gates and the aggregate Windows acceptance with zero critical failures.
