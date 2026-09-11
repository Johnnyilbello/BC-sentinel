# BC Sentinel v0.11.0-beta.6 — B6-0 Technician UX Foundation

## Purpose
B6-0 introduces the first graphical technician shell above the frozen Beta5 Portable Technician Release. It is a UX/state-model milestone only. It does not add rescue authority or change any Beta3/Beta4/Beta5 engine behavior.

## Frozen predecessor
```text
checkpoint/v011-beta5-b57-pass
16676519e3e43d9916e5e4281813bd75c9eebd7e
```

## Profile
```text
v0.11.0-beta.6-b60
bc-sentinel-beta6-technician-ui-model-v1
```

## Exact frozen engine commands
The UI contract must match B5-7 exactly:

- `plan`
- `scan`
- `repair-handoff`
- `data-rescue`
- `certify`
- `discover`
- `assess`
- `stress`
- `resume`
- `decide`
- `report`

The B6-0 shell performs no command automatically at startup.

## Forbidden UI commands
The following must remain absent:

- `repair-execute`
- `quarantine-execute`
- `unlock`
- `mount-write`
- `format`
- `reimage`
- `registry-write`
- `boot-write`

## UI state model
B6-0 uses only:

- `IDLE`
- `READY`
- `RUNNING`
- `REVIEW`
- `REFUSED`
- `ERROR`

`RECOVERED` is deliberately not a UI workflow state. Recovery certification remains an RR-6 outcome and must never be inferred from UI state.

## Initial state
At application startup:
- state is `IDLE`;
- no target selected;
- no target fingerprint;
- no workspace/evidence path;
- no session/correlation ID;
- no last engine command;
- no engine command dispatch;
- no worker/subprocess started.

## PySide6 shell
The shell provides:
- visible safety boundary;
- target/session/engine summary cards;
- disabled foundation workflow rows for discovery, assessment, evidence collection, decision review and report;
- inspectable safety-contract message;
- no active rescue action in B6-0.

The disabled actions become functional only in later milestones after their own acceptance gates.

## Safety contract
B6-0 adds no:
- automatic repair;
- automatic quarantine;
- automatic destructive action;
- repair execution;
- unlock;
- format/reimage execution;
- target execution;
- installer/service/driver requirement;
- network/cloud requirement.

RR-6 outcomes remain exactly:
- `RECOVERED`
- `NOT_RECOVERED`
- `INDETERMINATE_REFUSED`

## Acceptance
B6-0 passes only if:
1. complete accepted B5-7 gate passes first;
2. 16 B6-0 tests pass;
3. engine profile is exactly B5-7;
4. engine command inventory is exact;
5. forbidden commands remain absent;
6. initial state is empty/IDLE;
7. Qt shell constructs in offscreen mode;
8. foundation workflow actions are disabled;
9. startup dispatch remains false;
10. no service is installed;
11. B2 protected sources remain unchanged.

Expected cumulative coverage after PASS: **337 tests** (321 accepted predecessor coverage + 16 B6-0 tests).

## Files added
- `sentinel/rescue_technician_ui_model.py`
- `sentinel/rescue_technician_ui.py`
- `packaging/rescue_technician_ui_entry.py`
- `tests/test_v011_beta6_b60_technician_ux_foundation.py`
- `tools/v011_beta6_b60_acceptance.py`
- `TEST-V011-BETA6-B60.ps1`
- `RESUME-V011-BETA6-B60.ps1`

No accepted predecessor runtime file is modified.
