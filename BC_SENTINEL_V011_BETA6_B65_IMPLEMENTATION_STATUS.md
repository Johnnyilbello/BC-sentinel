# BC Sentinel v0.11.0-beta.6 — B6-5 Implementation Status

Status: **B6-5.0→B6-5.8 ACCEPTED / B6-5.9 IMPLEMENTED — WINDOWS CI + LOCAL DEVICE ACCEPTANCE PENDING**

Active development branch:

```text
feature/v011-beta6-b659-quarantine-integrity
```

Accepted predecessor:

```text
B6-5.8 Persistent restore after application restart
checkpoint/v011-beta6-b658-pass
Accepted commit: 643cbd46a6d196c1d4379ba5d6992dee328c14f1
Windows CI run 34883835093: SUCCESS
Local Windows device acceptance: PASS on 2026-09-15
```

B6-5.8 local evidence is preserved in:

```text
BC_SENTINEL_V011_BETA6_B658_LOCAL_DEVICE_ACCEPTANCE_2026-09-15.md
```

## Accepted B6-5 checkpoints

```text
B6-5.0  Passive Guided Resolution                       PASS / CHECKPOINTED
B6-5.1  Passive provider boundary                       PASS / CHECKPOINTED
B6-5.2  Reversible action-plan + journal blueprint      PASS / CHECKPOINTED
B6-5.3  Explicit user confirmation gate                 PASS / CHECKPOINTED
B6-5.4  Execution-readiness boundary                    PASS / CHECKPOINTED
B6-5.5  Harmless fixture execution + rollback           PASS / WINDOWS + LOCAL DEVICE
B6-5.6  Real-file quarantine boundary                   PASS / WINDOWS + LOCAL DEVICE
B6-5.7  Home quarantine UX/execution integration        PASS / WINDOWS + LOCAL DEVICE
B6-5.8  Persistent restore after application restart    PASS / WINDOWS + LOCAL DEVICE
B6-5.9  Quarantine integrity / degraded-state visibility IMPLEMENTED / CI + LOCAL PENDING
```

## B6-5.8 accepted boundary

The accepted Home execution authority remains deliberately narrow:

- only explicit `QUARANTINE` for eligible `HIGH/CRITICAL` file findings;
- target identity bound to an explicit SHA-256;
- only non-privileged regular files under Desktop, Documents or Downloads;
- AppData, Windows/system, Program Files, ProgramData, BC Sentinel source/runtime and symlink/reparse escapes remain blocked;
- explicit user click and second confirmation are required;
- provider creation remains lazy;
- persistent restore after a new process starts is supported only after record, permit, journal, quarantine artifact, rollback snapshot and SHA-256 checks succeed;
- restore refuses an occupied original target path and never overwrites it.

B6-5.8 local acceptance verified `9 passed`, fresh-process reconstruction, read-only restart discovery, explicit restore and an SHA-256 identical to the original.

## B6-5.9 — quarantine integrity visibility

B6-5.8 correctly failed closed when persistent recovery evidence was damaged or inconsistent, but those states could disappear from the ordinary **Quarantena** list because invalid records were intentionally excluded from the set of restorable items.

B6-5.9 fixes the visibility gap without opening any new mutation authority.

A new read-only integrity layer inspects the existing B6-5.8 recovery records and classifies degraded persistent states such as:

- recovery record unreadable or hash integrity mismatch;
- finding/permit/result binding mismatch;
- journal chain or journal anchor mismatch;
- original target collision;
- recovery artifact outside the dedicated protected roots;
- missing quarantine or rollback snapshot;
- quarantine/snapshot SHA-256 mismatch.

Verified active quarantines continue to appear with:

```text
Stato: In quarantena
Azione: Ripristina file
integrity_state = VERIFIED
```

A degraded persistent state instead appears with:

```text
Stato: Verifica richiesta
Azione: Ripristino bloccato
integrity_state = BLOCKED
restore_key = ""
```

Because the blocked row has no `restore_key`, the UI does not attach a `Ripristina file` button to it. The underlying B6-5.8 rollback path also remains fail-closed.

## Read-only guarantee

The B6-5.9 audit:

- does not instantiate a new mutating provider;
- does not create storage when no quarantine storage exists;
- does not rewrite recovery records;
- does not append journal events;
- does not clean up damaged metadata automatically;
- does not restore, delete or repair any file automatically.

The deterministic gate includes explicit byte-for-byte storage comparison around degraded-state discovery.

## B6-5.9 test/acceptance scope

Deterministic tests verify:

1. B6-5.8 remains the accepted predecessor;
2. a verified persistent quarantine keeps the existing explicit restore path;
3. a tampered recovery record is visible as blocked and receives no restore key;
4. a missing rollback snapshot is visible and non-actionable;
5. an occupied original path is visible and never overwritten;
6. integrity discovery is read-only and does not create storage.

The B6-5.9 fresh-process acceptance creates two controlled quarantines:

```text
Process A
  verified quarantine A
  verified quarantine B
  -> controlled integrity corruption of B recovery metadata
  -> exit

Process B
  fresh process
  -> A visible as VERIFIED + Ripristina file
  -> B visible as Verifica richiesta + Ripristino bloccato
  -> discovery bytes unchanged
  -> restore B refused
  -> restore A succeeds
  -> A SHA-256 identical to original
  -> B remains quarantined / not auto-restored
```

## Home authority after B6-5.9

```text
Passive capability provider = accepted
General Home execution = false
General live_home_execution_authorized = false
Home explicit quarantine = true, gated
Persistent explicit restore = true, gated
Read-only integrity visibility = true
Automatic cleanup = false
Automatic quarantine = false
Automatic restore = false
Automatic repair = false
DELETE = false
REPAIR = false
TERMINATE_PROCESS = false
TRUST/ALLOWLIST mutation = false
Privileged/system-file mutation = false
```

B6-5.9 is intentionally a hardening/observability milestone. It does **not** authorize a broader remediation action class.

## Local acceptance command

After Windows CI is green, run from the repository root:

```powershell
git fetch origin; git checkout feature/v011-beta6-b659-quarantine-integrity; git pull --ff-only origin feature/v011-beta6-b659-quarantine-integrity; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA6-B659.ps1" -ConfirmQuarantineIntegrityAcceptance -OpenUI
```

Do not create `checkpoint/v011-beta6-b659-pass` until that local-device gate passes.

Recommended reasoning for any future execution-authority expansion: **Extra High**.
