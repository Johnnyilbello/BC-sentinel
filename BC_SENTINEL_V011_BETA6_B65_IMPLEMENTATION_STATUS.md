# BC Sentinel v0.11.0-beta.6 — B6-5 Implementation Status

Status: **B6-5.0→B6-5.9 ACCEPTED / B6-5.9 WINDOWS CI + LOCAL WINDOWS DEVICE PASS**

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

Accepted B6-5.9:

```text
B6-5.9 Quarantine integrity / degraded-state visibility
checkpoint/v011-beta6-b659-pass
Accepted commit: 72c18bbdf1c50c633343750ead0f2467d8705e12
Windows CI run 34964434264: SUCCESS
Local Windows device acceptance: PASS on 2026-09-15
```

Local acceptance evidence:

```text
BC_SENTINEL_V011_BETA6_B658_LOCAL_DEVICE_ACCEPTANCE_2026-09-15.md
BC_SENTINEL_V011_BETA6_B659_LOCAL_DEVICE_ACCEPTANCE_2026-09-15.md
```

## Accepted B6-5 checkpoints

```text
B6-5.0  Passive Guided Resolution                        PASS / CHECKPOINTED
B6-5.1  Passive provider boundary                        PASS / CHECKPOINTED
B6-5.2  Reversible action-plan + journal blueprint       PASS / CHECKPOINTED
B6-5.3  Explicit user confirmation gate                  PASS / CHECKPOINTED
B6-5.4  Execution-readiness boundary                     PASS / CHECKPOINTED
B6-5.5  Harmless fixture execution + rollback            PASS / WINDOWS + LOCAL DEVICE
B6-5.6  Real-file quarantine boundary                    PASS / WINDOWS + LOCAL DEVICE
B6-5.7  Home quarantine UX/execution integration         PASS / WINDOWS + LOCAL DEVICE
B6-5.8  Persistent restore after application restart     PASS / WINDOWS + LOCAL DEVICE
B6-5.9  Quarantine integrity / degraded-state visibility PASS / WINDOWS + LOCAL DEVICE
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

## B6-5.9 accepted quarantine integrity visibility

B6-5.8 correctly failed closed when persistent recovery evidence was damaged or inconsistent, but those states could disappear from the ordinary **Quarantena** list because invalid records were intentionally excluded from the set of restorable items.

B6-5.9 closes that visibility gap without opening any new mutation authority.

A read-only integrity layer inspects the existing B6-5.8 recovery records and classifies degraded persistent states such as:

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

A degraded persistent state appears with:

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

## B6-5.9 automated evidence

Windows GitHub Actions:

```text
Run: 34964434264
Commit: 98f0ba743dd95f00d61f7c62ac9aa376110af257
Conclusion: SUCCESS

Compile B6-5.9 + predecessors: PASS
B6-0 → B6-5.9 deterministic regression suite: PASS
B6-3 predecessor acceptance: PASS
B6-4 passive self-check: PASS
B6-5.5 predecessor acceptance: PASS
B6-5.6 predecessor acceptance: PASS
B6-5.7 predecessor acceptance: PASS
B6-5.8 fresh-process persistent restore acceptance: PASS
B6-5.9 degraded integrity visibility acceptance: PASS
B6-5.9 Qt offscreen smoke: PASS
```

## B6-5.9 local Windows evidence

The local-device gate was executed against exact accepted commit:

```text
72c18bbdf1c50c633343750ead0f2467d8705e12
```

Results:

```text
11 passed in 0.75s
Deterministic gate: PASS
fresh_process_verified = true
verified_row_visible = true
blocked_integrity_row_visible = true
blocked_restore_refused = true
blocked_target_not_restored = true
restart_discovery_read_only = true
valid_restore_verified = true
valid_sha256_identical = true
general_home_execution_authorized = false
automatic_cleanup = false
automatic_quarantine = false
delete_authorized = false
repair_authorized = false
Self-check B6-5.9: PASS
Real UI preflight/open/normal close: PASS
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

## UI product-polish follow-up

Functional acceptance is closed. The next UI-only cleanup should remove internal milestone/provider terminology from the user-facing product without changing security behavior:

- replace the stale Quarantena empty-state copy that still says a real quarantine provider is not connected;
- replace `Quick Scan · B6-3` with a user-facing label such as `Scansione rapida`;
- localize internal Threat Card/provider identifiers such as `Static scanner assessment`, `static_malware_scan` and `smart_scope_04`, retaining raw identifiers only inside advanced technical details.

These are product-polish changes only and must remain separate from the accepted B6-5.9 checkpoint.

Recommended reasoning for any future execution-authority expansion: **Extra High**.
