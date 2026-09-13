# BC Sentinel v0.11.0-beta.6 — B6-3.5 Live Home UI Cancellation Acceptance

Date: 2026-09-13

Status: **PASS**

Branch: `feature/v011-beta6-b63-smart-scan`

## Objective

Verify that the actual B6-3 Home UI drives cancellation through the same accepted Smart Scan coordinator path while the real pinned historical runtime is active, without freezing the UI or enabling remediation authority.

## Test path

The Home was launched through `RUN-V011-BETA6-B635-LIVE-UI.ps1` in `cancel` mode with the pinned historical `StaticScanner` runtime. The probe started Smart Scan by clicking the real Home Smart Scan control and, after two seconds in `RUNNING`, clicked the real `Annulla` button.

Scope used:

```text
max files: 250
max total: 128 MB
max file: 64 MB
recent window: 90 days
```

Pinned scanner SHA-256:

```text
7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433
```

## Observed result

```text
passed=true
mode=cancel
cancel_click_sent=true
state=CANCELLED
coverage=INCOMPLETE
elapsed_ms=7047
findings_count=1
heartbeat_ticks_while_running=36
max_heartbeat_gap_ms=125.0
progress_advanced=true
progress_sample_count=9
dashboard_horizontal_scroll_max=0
scan_page_horizontal_scroll_max=0
```

The result is intentionally `INCOMPLETE`: a user-cancelled scan must never be represented as complete or clean.

## Acceptance conclusions

- the actual Home Smart Scan button starts the accepted live provider path;
- the actual Home `Annulla` button reaches the coordinator cancellation path;
- the terminal state is `CANCELLED`;
- coverage remains truthful as `INCOMPLETE`;
- already-produced evidence/findings are preserved;
- UI progress visibly advances before cancellation;
- the Qt event loop remains responsive during the live scan;
- Dashboard and Scan page have zero horizontal overflow when measured while visible;
- no automatic quarantine, repair or destructive action is enabled.

## Non-blocking observation

PySide emitted existing `clicked().disconnect()` runtime warnings from the B6-2/B6-3 shell. They did not affect scan execution, progress, cancellation, responsiveness or the terminal result and remain a cleanup item rather than a security/functionality gate failure.

## Evidence file generated locally

```text
acceptance-v011-beta6-b635-live-ui-cancel.json
```

This checkpoint completes the live Home/UI cancellation acceptance required for B6-3 stabilization. Final promotion still requires the full Windows predecessor/B6-3 CI gate to be green on the final stabilization head.