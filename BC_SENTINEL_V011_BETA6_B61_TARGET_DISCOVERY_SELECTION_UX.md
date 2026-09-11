# BC Sentinel v0.11.0-beta.6 — B6-1 Target Discovery & Selection UX

## Purpose
Provide a technician-facing graphical target picker over the already accepted B5-0 target discovery contract without changing discovery authority or the frozen B6-0 foundation.

## Frozen predecessors
- Beta5 final portable technician engine: `checkpoint/v011-beta5-b57-pass`
- B6-0 Technician UX Foundation: `checkpoint/v011-beta6-b60-pass`

B6-1 adds new modules only for target discovery/selection behavior. It does not modify the B5-0 discovery engine or B6-0 source modules.

## State mapping
B5-0 states are rendered distinctly and preserved exactly:
- `READY`
- `LOCKED`
- `ACCESS_DENIED`
- `INCOMPLETE`
- `UNSUPPORTED`
- `ERROR`

A target is selectable only when:
1. state is exactly `READY`;
2. the B5-0 record has `write_attempted=false`;
3. target fingerprint is exactly 64 lowercase hexadecimal SHA-256 characters;
4. the full B5-0 result passes the frozen safety contract.

No non-READY state can be promoted by the UI.

## Live SystemDrive
The active Windows SystemDrive is not an offline rescue target. B5-0 must classify it as:

```text
UNSUPPORTED
reason=live_system_volume_refused
```

The UI displays that refusal rather than hiding the drive or offering a workaround.

## Operator gating
- discovery starts only after explicit `Discover targets` action;
- no discovery at application startup;
- no target is selected automatically after discovery;
- the operator must select one row and explicitly choose `Use selected target`;
- `Use selected target` remains disabled for all non-READY rows;
- the selected target path and RR-6 fingerprint are bound into the UI state.

## Safety boundaries
B6-1 does not expose or perform:
- BitLocker unlock;
- mount-for-write;
- disk format;
- partition writes;
- BCD/boot writes;
- filesystem repair;
- target execution;
- repair execution;
- quarantine execution;
- automatic target selection;
- automatic destructive action.

## UI architecture
B6-1 extends B6-0 through new files:
- `sentinel/rescue_technician_target_selection.py`
- `sentinel/rescue_technician_ui_b61.py`
- `packaging/rescue_technician_ui_b61_entry.py`

Frozen B6-0 UI/model files remain unchanged.

## Acceptance
The authoritative Windows gate must prove:
- complete accepted B6-0 predecessor gate remains PASS;
- 20 B6-1 deterministic/UI tests PASS;
- controlled `READY`, `LOCKED`, `INCOMPLETE`, `UNSUPPORTED` targets render distinctly;
- only READY target is selectable;
- ready fingerprint is visible and bound into selected UI state;
- locked target cannot be selected;
- live SystemDrive is `UNSUPPORTED/live_system_volume_refused`;
- no unlock or mount-write UI action exists;
- controlled targets remain byte-identical;
- no B6-1 Windows service is registered;
- protected B2 service/realtime/EDR sources remain unchanged.

## Observability
On failure the Windows gate reports an exact stage plus relevant counts/state/fingerprint. Acceptance JSON includes discovery session ID, correlation ID, state counts, selected target/fingerprint, live SystemDrive state/reason and exposed command properties.
