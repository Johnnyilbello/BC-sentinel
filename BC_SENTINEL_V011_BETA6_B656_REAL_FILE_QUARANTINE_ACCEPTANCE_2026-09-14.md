# BC Sentinel v0.11.0-beta.6 — B6-5.6 Real-file Quarantine Acceptance

Date: 2026-09-14
Branch: `feature/v011-beta6-b65-guided-resolution`
Verified implementation commit: `b5c5cb518a4adfcee744a7c7374ae5bd982eb910`
Checkpoint: `checkpoint/v011-beta6-b656-pass`
GitHub Actions run: `34857491930`

## Result

**PASS — controlled real user-profile file quarantine boundary + verified rollback on Windows CI.**

The accepted B6-5.6 scope extends B6-5.5 from a TEMP-only fixture to one explicit non-privileged file under the current user's Desktop, Documents or Downloads. The CI acceptance itself creates a dedicated test-owned file under `Documents\BCSentinel-B656-Acceptance-*`; it never selects an existing personal file automatically.

Reported acceptance:

```text
checkpoint = B6-5.6-real-file-quarantine-boundary
passed = true
real_user_profile_scope = true
restored_state_verified = true
journal_passed = true
cleanup_verified = true
live_home_execution_authorized = false
```

Full regression gate:

```text
197 passed, 36 warnings
B6-3 predecessor acceptance: PASS
B6-4 predecessor self-check: PASS
B6-5.5 fixture execution predecessor acceptance: PASS
B6-5.6 controlled real-file quarantine + rollback acceptance: PASS
B6-5.6 Qt offscreen smoke: PASS
```

## Accepted safety boundary

Only `QUARANTINE` is supported. Before execution the provider requires:

- an exact B6-5.2 plan and target SHA-256;
- a valid explicit B6-5.3 human confirmation receipt;
- fresh post-confirmation SHA-256/path revalidation;
- a short-lived one-shot permit;
- an accepted fixed execution-provider snapshot;
- a verified rollback snapshot;
- append-only hash-chained journal evidence.

Target eligibility is fail-closed. B6-5.6 allows only regular files at or below 64 MiB under the current user's Desktop, Documents or Downloads and refuses protected/self-managed locations, AppData, system paths, Program Files, ProgramData, BC Sentinel source/runtime paths, symlink/path escapes and unresolved targets.

## What remains disabled

```text
live_home_execution_authorized = false
automatic_action = false
destructive_authority = false
DELETE = unauthorized
REPAIR = unauthorized
TERMINATE_PROCESS = unauthorized
TRUST/ALLOWLIST mutation = unauthorized
privileged/system-file mutation = unauthorized
```

B6-5.6 proves the real-file execution boundary in a controlled acceptance path. It does not yet expose quarantine execution in the normal Home UI and does not authorize arbitrary automatic remediation.

## Local acceptance still required

The next gate is the same one-command B6-5.6 acceptance on the user's Windows device. It creates its own controlled file under Documents, quarantines it, verifies the journal and hashes, restores it, verifies the original SHA-256, and cleans up the acceptance-owned files. Only after that local-device PASS should B6-5.6 be considered closed for its declared scope.
