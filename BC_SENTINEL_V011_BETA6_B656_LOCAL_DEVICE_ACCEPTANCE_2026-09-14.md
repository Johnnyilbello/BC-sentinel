# BC Sentinel v0.11.0-beta.6 — B6-5.6 Local Device Acceptance — 2026-09-14

Result: **PASS**

Tested branch:

```text
feature/v011-beta6-b65-guided-resolution
```

Tested commit:

```text
c3fa166cd1f47a8306547a8e37f2d85badee87d9
```

Execution environment: user's Windows PC, local repository `BC-Sentinel-B61`.

Command used:

```powershell
git fetch origin; git checkout feature/v011-beta6-b65-guided-resolution; git pull --ff-only origin feature/v011-beta6-b65-guided-resolution; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA6-B656.ps1" -ConfirmRealFileAcceptance
```

## Deterministic gate

```text
pytest: 9.1.1
pytest basetemp: %LOCALAPPDATA%\Temp\BCSentinel-B656-Pytest-<unique>
7 passed in 0.25s
Deterministic gate: PASS
```

The final launcher deliberately keeps pytest's temporary tree outside the BC Sentinel repository so the self-managed-path protection remains enabled and test artifacts are not misclassified as eligible user targets.

## Controlled real-file acceptance

The launcher created only its own controlled file under:

```text
%USERPROFILE%\Documents\BCSentinel-B656-Acceptance-*
```

No existing personal file was selected automatically.

Observed result:

```text
checkpoint = B6-5.6-real-file-quarantine-boundary
passed = true
real_user_profile_scope = true
restored_state_verified = true
journal_passed = true
cleanup_verified = true
live_home_execution_authorized = false
```

Console summary:

```text
B6-5.6 real-file quarantine boundary acceptance PASS.
Rollback verificato: True
Journal verificato: True
Cleanup verificato: True
Live Home execution autorizzata: False
```

## Acceptance conclusion

B6-5.6 is accepted on both Windows CI and the local Windows device. The reversible real-file quarantine boundary is verified for one explicit, non-privileged user file while general Home execution remains disabled.

This acceptance does **not** authorize DELETE, REPAIR, TERMINATE_PROCESS, TRUST/ALLOWLIST mutation, privileged/system-file mutation or automatic remediation.
