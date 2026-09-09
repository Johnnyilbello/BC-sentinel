# BC Sentinel v0.1.3 — Quarantine State Sync

Fixes:
- detection history now tracks the current quarantine state;
- restoring a file updates the latest detection action to `restored`;
- permanent deletion updates the latest detection action to `deleted`;
- history displays localized action labels:
  - Rilevato
  - In quarantena
  - Ripristinato
  - Eliminato
- quarantine records remain preserved for audit/history.

No detection thresholds or scanning heuristics changed in this release.
