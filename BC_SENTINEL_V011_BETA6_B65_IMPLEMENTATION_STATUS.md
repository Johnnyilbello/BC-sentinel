# BC Sentinel v0.11.0-beta.6 — B6-5 Implementation Status

Status: **B6-5.0→B6-5.8 ACCEPTED INCREMENTALLY / B6-5.8 WINDOWS CI + LOCAL WINDOWS DEVICE PASS**

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

B6-5.7 Home quarantine UX/execution integration
checkpoint/v011-beta6-b657-pass
Accepted commit: c7ae2ee14d7a2551b632d003c4d174a6d6ae63c1
Windows CI: PASS
Local Windows device acceptance: PASS on 2026-09-14

B6-5.8 Persistent restore after application restart
checkpoint/v011-beta6-b658-pass
Accepted commit: 643cbd46a6d196c1d4379ba5d6992dee328c14f1
Windows CI run 34883835093: SUCCESS
Local Windows device acceptance: PASS on 2026-09-15
```

## Local B6-5.8 evidence

```text
9 deterministic tests passed
fresh_process_restart_verified = true
persistent_active_after_restart = true
persistent_restore_verified = true
quarantine_page_row_after_restart = true
recovery_record_created_before_restart = true
restart_discovery_read_only = true
restored_sha256_identical = true
rows_cleared_after_restore = true
general_home_execution_authorized = false
automatic_quarantine = false
delete_authorized = false
repair_authorized = false
self_check = PASS
real_UI_session = PASS
```

Evidence file:

```text
BC_SENTINEL_V011_BETA6_B658_LOCAL_DEVICE_ACCEPTANCE_2026-09-15.md
```

B6-5.8 is closed. The accepted checkpoint remains fixed at the exact code commit that passed both Windows CI and the local Windows device gate.

## Progress

```text
B6-5.0  Passive decision + Guided Resolution UI        PASS / CHECKPOINTED
B6-5.1  Passive provider boundary                      PASS / CHECKPOINTED
B6-5.2  Reversible action-plan + journal blueprint     PASS / CHECKPOINTED
B6-5.3  Explicit user confirmation gate                PASS / CHECKPOINTED
B6-5.4  Execution-readiness boundary                   PASS / CHECKPOINTED
B6-5.5  Harmless fixture execution + rollback          PASS / WINDOWS + LOCAL DEVICE
B6-5.6  Real-file quarantine boundary                  PASS / WINDOWS + LOCAL DEVICE
B6-5.7  Home quarantine UX/execution integration       PASS / WINDOWS + LOCAL DEVICE
B6-5.8  Persistent restore after application restart   PASS / WINDOWS + LOCAL DEVICE
```

## B6-5.7 accepted Home quarantine integration

B6-5.7 exposed only the accepted reversible B6-5.6 `QUARANTINE` action inside the everyday Home flow. It did not create general remediation authority.

The per-finding Home quarantine action remains available only when all of the following are true:

- severity is `HIGH` or `CRITICAL`;
- the Threat Card contains one explicit SHA-256 for a file target;
- the target is a regular file under Desktop, Documents or Downloads;
- the target is not AppData, Windows/system, Program Files, ProgramData, BC Sentinel source/runtime, a protected/self-managed path or a symlink/reparse escape;
- the current SHA-256 still matches the scan evidence;
- the user clicks `Metti in quarantena` explicitly;
- a second confirmation dialog is accepted;
- SHA-256 is revalidated at confirmation and again after confirmation;
- the one-shot B6-5.6 execution permit is valid.

The execution provider remains lazy: opening Home, navigating, refreshing or rendering findings does not instantiate the mutating provider and does not create quarantine storage.

## B6-5.8 accepted persistent restore after restart

B6-5.8 removes the B6-5.7 session-bound restore limitation without broadening remediation authority.

After explicit confirmation and before the target file is moved, Home writes an atomic recovery record under the dedicated B6-5.6 LocalAppData storage:

```text
%LOCALAPPDATA%\BCSentinel\B656\home-restore\
```

The recovery record binds the exact finding and B6-5.6 execution permit. After verified quarantine it is finalized with the verified execution result. If finalization is interrupted, the durable `PREPARED` record plus the hash-chained B6-5.6 journal can reconstruct the same verified result after restart.

Restart discovery is read-only. Merely opening BC Sentinel:

- does not instantiate the mutating quarantine provider;
- does not rewrite the recovery record;
- does not append to the journal;
- does not restore or quarantine anything automatically.

A persisted restore candidate is exposed only if all required evidence still agrees:

- recovery-record integrity is valid;
- finding ID and permit are bound;
- B6-5.6 permit integrity validates;
- B6-5.6 result integrity validates or can be reconstructed from the journal;
- the journal hash chain validates;
- the `ACTION_RESULT` journal anchor matches the permit, target, SHA-256 and quarantine artifact;
- the original target location is still absent;
- quarantine artifact is still inside the dedicated quarantine root;
- rollback snapshot is still inside the dedicated rollback root;
- quarantine artifact SHA-256 equals the original target SHA-256;
- rollback snapshot SHA-256 equals the original target SHA-256.

The **Quarantena** page reconstructs verified active rows after a new application process starts and exposes `Ripristina file`. The restore command is explicit and asks for confirmation in the UI. The B6-5.6 provider is created only at that point, then performs the existing verified rollback. The restored file must have the original SHA-256.

If the persistent record, journal, target state or artifacts do not validate, restore fails closed and no file is overwritten.

## B6-5.8 automated evidence

Windows GitHub Actions:

```text
Run: 34883835093
Conclusion: SUCCESS

Compile B6-5.8 + predecessors: PASS
B6-0 → B6-5.8 deterministic regression suite: PASS
B6-5.5 predecessor acceptance: PASS
B6-5.6 predecessor acceptance: PASS
B6-5.7 predecessor acceptance: PASS
B6-5.8 fresh-process persistent restore acceptance: PASS
B6-5.8 Qt offscreen smoke: PASS
```

The B6-5.8 acceptance uses two separate Python processes:

```text
Process A
  explicit confirmation
  -> quarantine
  -> durable recovery record + journal

Process B
  fresh process
  -> read-only recovery discovery
  -> Quarantine row reconstructed
  -> explicit restore
  -> SHA-256 identical to original
```

The deterministic B6-5.8 tests also verify fail-closed behavior for a tampered recovery record and an occupied original target path.

## B6-5.8 local Windows acceptance

The local-device gate was executed against accepted commit `643cbd46a6d196c1d4379ba5d6992dee328c14f1` with the real B6-5.8 launcher and `-OpenUI`.

Verified locally:

```text
9 tests: PASS
Process A quarantine: PASS
Fresh Process B restart discovery: PASS
Persistent quarantine reconstruction: PASS
Quarantine page row after restart: PASS
Restart discovery read-only: PASS
Explicit persistent restore: PASS
Restored SHA-256 identical: PASS
Rows cleared after restore: PASS
B6-5.8 self-check: PASS
Real UI preflight/open/normal close: PASS
```

The local output also reconfirmed:

```text
general_home_execution_authorized = false
automatic_quarantine = false
delete_authorized = false
repair_authorized = false
```

## Home authority after B6-5.8

```text
Passive capability provider = accepted
General Home execution = false
General live_home_execution_authorized = false
Home explicit quarantine action = true, gated
Persistent explicit restore = true, gated
Eligible severity = HIGH / CRITICAL only
Automatic quarantine = false
Automatic restore = false
Automatic repair = false
DELETE = false
REPAIR = false
TERMINATE_PROCESS = false
TRUST/ALLOWLIST mutation = false
Privileged/system-file mutation = false
```

This distinction remains intentional: B6-5.8 authorizes only the narrow reversible quarantine/restore lifecycle. It does not authorize broad remediation.

## UI quality state

The accepted screenshot-driven polish remains in force:

- Smart Scan wrapped copy uses content-driven height;
- Quarantine empty state has no hard vertical cap;
- Cronologia empty state and command container have no hard vertical caps;
- `Aggiorna stato` and `Aggiorna lista` use distinct semantic icons;
- historical runtime recommendation copy is localized without mutating raw evidence;
- quarantine controls remain subordinate to verified evidence;
- active persistent rows expose a real `Ripristina file` control rather than a text-only placeholder.

## Safety sequence

1. passive capability proof — B6-5.1 ✅;
2. immutable action-plan + target/evidence binding — B6-5.2 ✅;
3. explicit confirmation bound to the exact plan — B6-5.3 ✅;
4. separate execution-readiness gate — B6-5.4 ✅;
5. harmless fixture-only execution + journal + rollback — B6-5.5 ✅;
6. explicit non-privileged real-file quarantine boundary — B6-5.6 ✅ Windows + local device;
7. explicit Home quarantine UX/integration — B6-5.7 ✅ Windows + local device;
8. restart-safe persistent restore — B6-5.8 ✅ Windows CI + local device;
9. any broader action class requires a separate future gate.

Recommended reasoning for post-B6-5.8 execution-authority work: **Extra High**.
