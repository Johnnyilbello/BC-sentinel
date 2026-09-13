# BC Sentinel v0.11.0-beta.6 — B6-3.5 Live Home/UI Complete-Mode Acceptance

Date: 2026-09-13
Branch: `feature/v011-beta6-b63-smart-scan`
Tested head: `d33cc7eecb76f644006be310b1bb1a755cd95a14`

## Result

**PASS**

The actual B6-3 Home was launched against the accepted pinned historical FULL runtime. Smart Scan was started through the real Home UI control and completed through the worker-thread path.

Observed summary:

```text
checkpoint=B6-3.5-live-home-ui
mode=complete
passed=true
failures=[]
state=COMPLETED_FINDINGS
coverage=COMPLETE
elapsed_ms=7984
findings_count=7
progress_advanced=true
progress_sample_count=17
heartbeat_ticks_while_running=46
max_heartbeat_gap_ms≈110
dashboard_horizontal_scroll_max=0
scan_page_horizontal_scroll_max=0
```

## Acceptance conclusions

- the accepted pinned runtime was available to the actual Home;
- Smart Scan was started through the real UI action, not by bypassing the Home;
- the scan ran outside the GUI thread;
- the UI event loop remained responsive during real scanning;
- visible file-level progress advanced during the run;
- launch controls were disabled while scanning;
- the Cancel control was available while scanning;
- the terminal result was rendered in the real scan page;
- Advanced details remained available after completion;
- the bounded Smart Scan plan completed with `coverage=COMPLETE`;
- both visible Dashboard and scan page reported zero horizontal overflow after explicit visible-page reflow;
- no quarantine, repair, process termination, deletion, registry/boot write, unlock, write mount, format or reimage authority was introduced.

The earlier complete-mode probe failure was only `dashboard_horizontal_overflow` while the Dashboard QScrollArea was hidden behind the scan page in the QStackedWidget. The acceptance probe was corrected to measure Dashboard overflow only after making Dashboard visible and forcing geometry/width synchronization. The repeated real run then passed with both horizontal scrollbar maxima equal to zero.

## Remaining B6-3.5 work

The remaining live UI acceptance item is the UI-driven cancellation run: the real Home Cancel button must be clicked during an active pinned-runtime scan and must produce `state=CANCELLED`, `coverage=INCOMPLETE`, preserve already-produced evidence, keep the UI responsive, and retain zero destructive authority.

B6-3 is not promoted stable by this checkpoint alone.
