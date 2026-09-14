# BC Sentinel v0.11.0-beta.6 — B6-5 Implementation Status

Status: **B6-5.0→B6-5.6 ACCEPTED INCREMENTALLY / B6-5.6 WINDOWS CI GREEN / LOCAL DEVICE ACCEPTANCE PENDING**

Active development branch:

```text
feature/v011-beta6-b65-guided-resolution
```

Accepted stable predecessor:

```text
B6-4 Threat Cards + Advanced Details
c3fbac9e89edff6b08490da3dd593300e816fa30
checkpoint/v011-beta6-b64-pass
stable/v011-beta6-b64
```

Accepted B6-5 development checkpoints:

```text
B6-5.0 Passive Guided Resolution
checkpoint/v011-beta6-b650-pass

B6-5.1 Passive provider boundary
checkpoint/v011-beta6-b651-pass
Windows CI run 34845635971: SUCCESS

B6-5.2 Reversible action-plan + journal blueprint
checkpoint/v011-beta6-b652-pass

B6-5.2 UI refinement
checkpoint/v011-beta6-b652-ui-refinement-pass

B6-5.3 Explicit confirmation gate
checkpoint/v011-beta6-b653-pass

B6-5.4 Execution-readiness boundary
105901b753da925fd5b3b8ec9d74c8e448bc7d7b
checkpoint/v011-beta6-b654-pass

B6-5.5 Harmless fixture execution + rollback
checkpoint/v011-beta6-b655-pass
Windows CI run 34855442176: SUCCESS
Local Windows device acceptance: PASS (2026-09-14)

B6-5.6 Real-file quarantine boundary
b5c5cb518a4adfcee744a7c7374ae5bd982eb910
checkpoint/v011-beta6-b656-pass
Windows CI run 34857491930: SUCCESS
Local Windows device acceptance: PENDING
```

## Progress

```text
B6-5.0  Passive decision + Guided Resolution UI        PASS / CHECKPOINTED
B6-5.1  Passive provider boundary                      PASS / CHECKPOINTED
B6-5.2  Reversible action-plan + journal blueprint     PASS / CHECKPOINTED
B6-5.3  Explicit user confirmation gate                PASS / CHECKPOINTED
B6-5.4  Execution-readiness boundary                   PASS / CHECKPOINTED
B6-5.5  Harmless fixture execution + rollback          PASS / WINDOWS + LOCAL DEVICE
B6-5.6  Real-file quarantine boundary                  WINDOWS PASS / LOCAL DEVICE PENDING
B6-5.7  Home quarantine UX/execution integration       NOT STARTED
```

## Current Home authority

The normal product Home remains non-executing. B6-5.6 does not silently turn a detection or a confirmation into quarantine authority.

```text
Guided Resolution authority = REPORT_ONLY
Home capability provider = passive introspection only
Home execution provider loaded = false
Home execution_available = false
live_home_execution_authorized = false
Home journal_write_authority = false
Home rollback_execution_authority = false
automatic_quarantine = false
automatic_repair = false
automatic_destructive_action = false
```

## B6-5.6 controlled real-file authority

B6-5.6 introduces a separate execution provider for one explicit, non-privileged user file.

```text
authority_scope = EXPLICIT_NON_PRIVILEGED_USER_FILE_ONLY
supported action = QUARANTINE
allowed roots = Desktop / Documents / Downloads
maximum target size = 64 MiB
explicit confirmation = required
fresh SHA-256 revalidation = required
one-shot permit = required
hash-chained journal = required
verified rollback snapshot = required
live_home_execution_authorized = false
automatic_action = false
destructive_authority = false
```

Fail-closed eligibility refuses targets outside the allowed roots, AppData, Windows/system areas, Program Files, ProgramData, BC Sentinel source/runtime paths, protected/self-managed roots, symlink/path escapes, unresolved/non-regular targets and oversized files.

The Windows acceptance creates its own controlled file under the current user's Documents folder, executes the complete quarantine path, verifies the moved file and snapshot SHA-256, performs verified rollback, validates the journal chain and cleans up only acceptance-owned artifacts. It never selects an existing personal file automatically.

## B6-5.6 Windows acceptance

Verified implementation commit:

```text
b5c5cb518a4adfcee744a7c7374ae5bd982eb910
```

GitHub Actions run:

```text
34857491930
```

Result:

```text
197 passed, 36 warnings
B6-3 predecessor acceptance: PASS
B6-4 predecessor self-check: PASS
B6-5.5 fixture execution predecessor acceptance: PASS
B6-5.6 controlled real-file quarantine + rollback acceptance: PASS
B6-5.6 Qt offscreen smoke: PASS
```

B6-5.6 acceptance evidence:

```text
passed = true
real_user_profile_scope = true
restored_state_verified = true
journal_passed = true
cleanup_verified = true
live_home_execution_authorized = false
```

Evidence document:

```text
BC_SENTINEL_V011_BETA6_B656_REAL_FILE_QUARANTINE_ACCEPTANCE_2026-09-14.md
```

The 36 warnings are existing non-blocking predecessor PySide disconnect warnings plus GitHub runner/action deprecation noise.

## UI quality state

The current B6-5 Home carries the accepted UI polish from the real Windows visual review:

- Smart Scan wrapped copy uses content-driven height;
- Quarantine empty state no longer uses a hard vertical cap;
- History/Cronologia empty state and command container no longer use hard vertical caps;
- `Aggiorna stato` and `Aggiorna lista` use distinct semantic icon roles;
- primary historical-runtime recommendation copy is localized without mutating raw evidence;
- Home remains six-page, scroll-safe and non-executing.

B6-5.6 itself does not yet add a Home quarantine button. Home integration belongs to the next separately gated milestone so the accepted execution provider cannot leak into the everyday UI before local-device acceptance and UX review.

## Safety sequence

1. passive capability proof — B6-5.1 ✅;
2. immutable action-plan + target/evidence binding — B6-5.2 ✅;
3. explicit confirmation bound to the exact plan — B6-5.3 ✅;
4. separate execution-readiness gate — B6-5.4 ✅;
5. harmless fixture-only execution + journal + rollback — B6-5.5 ✅;
6. explicit non-privileged real-file quarantine boundary — B6-5.6 Windows ✅ / local device pending;
7. only after local acceptance: Home quarantine UX/integration, still explicit and reversible — B6-5.7;
8. broader action classes require their own future gates.

B6-5.6 does not authorize DELETE, REPAIR, TERMINATE_PROCESS, TRUST/ALLOWLIST mutation, privileged/system-file mutation or automatic remediation.

Recommended reasoning for B6-5.7 and later execution-authority work: **Extra High**.
