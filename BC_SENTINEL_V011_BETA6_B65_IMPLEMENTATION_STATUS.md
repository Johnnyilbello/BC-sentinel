# BC Sentinel v0.11.0-beta.6 — B6-5 Implementation Status

Status: **B6-5.0→B6-5.6 ACCEPTED INCREMENTALLY / B6-5.6 WINDOWS + LOCAL DEVICE PASS / B6-5.7 IMPLEMENTED — FINAL CI GATE PENDING**

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

## Accepted B6-5 checkpoints

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
checkpoint/v011-beta6-b654-pass

B6-5.5 Harmless fixture execution + rollback
checkpoint/v011-beta6-b655-pass
Windows CI run 34855442176: SUCCESS
Local Windows device acceptance: PASS

B6-5.6 Real-file quarantine boundary
checkpoint/v011-beta6-b656-pass
Windows CI: PASS
Local Windows device acceptance: PASS on 2026-09-14
```

Local B6-5.6 evidence:

```text
7 deterministic tests passed
real_user_profile_scope = true
restored_state_verified = true
journal_passed = true
cleanup_verified = true
live_home_execution_authorized = false
```

Evidence:

```text
BC_SENTINEL_V011_BETA6_B656_LOCAL_DEVICE_ACCEPTANCE_2026-09-14.md
```

## Progress

```text
B6-5.0  Passive decision + Guided Resolution UI        PASS / CHECKPOINTED
B6-5.1  Passive provider boundary                      PASS / CHECKPOINTED
B6-5.2  Reversible action-plan + journal blueprint     PASS / CHECKPOINTED
B6-5.3  Explicit user confirmation gate                PASS / CHECKPOINTED
B6-5.4  Execution-readiness boundary                   PASS / CHECKPOINTED
B6-5.5  Harmless fixture execution + rollback          PASS / WINDOWS + LOCAL DEVICE
B6-5.6  Real-file quarantine boundary                  PASS / WINDOWS + LOCAL DEVICE
B6-5.7  Home quarantine UX/execution integration       IMPLEMENTED / CI PENDING
```

## B6-5.7 Home quarantine integration

B6-5.7 exposes only the accepted reversible B6-5.6 `QUARANTINE` action inside the everyday Home flow. It does not create general remediation authority.

The per-finding Home action is available only when all of the following are true:

- severity is `HIGH` or `CRITICAL`;
- the Threat Card contains one explicit SHA-256 for a file target;
- the target is a regular file under Desktop, Documents or Downloads;
- the target is not AppData, Windows/system, Program Files, ProgramData, BC Sentinel source/runtime, a protected/self-managed path or a symlink/reparse escape;
- the current SHA-256 still matches the scan evidence;
- the user clicks `Metti in quarantena` explicitly;
- a second confirmation dialog is accepted;
- SHA-256 is revalidated at confirmation and again after confirmation;
- the one-shot B6-5.6 execution permit is valid.

The execution provider is lazy: opening Home, navigating, refreshing or rendering findings does not instantiate the mutating provider and does not create quarantine storage.

After successful quarantine the same Threat Card exposes `Ripristina file`. Rollback remains session-bound in B6-5.7 and verifies the restored SHA-256. The Quarantine page now reads active quarantine rows from the persistent B6-5.6 hash-chained journal without creating or mutating storage during startup.

Important limitation intentionally kept for the next gate:

```text
persistent_restore_after_restart = false
```

If the application is closed while a B6-5.7 item is quarantined, the persistent quarantine artifact, rollback snapshot and journal remain preserved, but the everyday Home does not yet reconstruct a restart-safe Restore command. That belongs to B6-5.8+.

## Home authority after B6-5.7

```text
Passive capability provider = accepted
General Home execution = false
General live_home_execution_authorized = false
Home explicit quarantine action = true, gated
Eligible severity = HIGH / CRITICAL only
Automatic quarantine = false
Automatic repair = false
DELETE = false
REPAIR = false
TERMINATE_PROCESS = false
TRUST/ALLOWLIST mutation = false
Privileged/system-file mutation = false
```

This distinction is intentional: B6-5.7 authorizes one narrow, reversible, user-mediated action class; it does not authorize broad remediation.

## UI quality state

The accepted screenshot-driven polish remains in force:

- Smart Scan wrapped copy uses content-driven height;
- Quarantine empty state has no hard vertical cap;
- Cronologia empty state and command container have no hard vertical caps;
- `Aggiorna stato` and `Aggiorna lista` use distinct semantic icons;
- historical runtime recommendation copy is localized without mutating raw evidence;
- all B6-5.7 quarantine controls are subordinate to Threat Card evidence and use explicit confirmation.

## Safety sequence

1. passive capability proof — B6-5.1 ✅;
2. immutable action-plan + target/evidence binding — B6-5.2 ✅;
3. explicit confirmation bound to the exact plan — B6-5.3 ✅;
4. separate execution-readiness gate — B6-5.4 ✅;
5. harmless fixture-only execution + journal + rollback — B6-5.5 ✅;
6. explicit non-privileged real-file quarantine boundary — B6-5.6 ✅ Windows + local device;
7. explicit Home quarantine UX/integration — B6-5.7 implemented, final CI gate pending;
8. restart-safe restore/persistent Home recovery and any broader action classes require separate future gates.

Recommended reasoning for B6-5.7+ execution-authority work: **Extra High**.
