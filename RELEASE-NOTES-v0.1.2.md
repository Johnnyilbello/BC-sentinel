# BC Sentinel v0.1.2 — Detection Hygiene

## Corrections
- `detections` now stores only score >= 50.
- SAFE and LOW telemetry no longer pollute the threat history.
- database-level hash+score deduplication suppresses repeated detections for 10 minutes.
- manual scans and real-time monitoring use the same persistence policy.
- history cleanup removes:
  - old SAFE/LOW rows,
  - duplicated hash/score rows,
  - legacy BC Sentinel self-detections from previous builds.
- quarantine UI is split into:
  - `In quarantena`
  - `Ripristinati`
- restored items no longer appear as active quarantine.
- `Pulisci cronologia precedente` added to Detection History.
- quarantine records are never deleted by history cleanup.

This release focuses on data quality before adding deeper endpoint telemetry.
