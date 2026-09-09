# BC Sentinel v0.1.4 — UI Refresh + Current-State History

## UI
- redesigned dashboard with clearer hierarchy;
- compact product header and version badge;
- professional protection module cards;
- dashboard statistics:
  - last scan;
  - active detections;
  - files in quarantine;
- cleaner scan progress area;
- improved tables and tabs;
- improved quarantine page;
- improved history page;
- stronger visual distinction between normal, primary and destructive actions.

## History
- detection history now shows one current row per SHA-256;
- historical contradictory states no longer appear together in the primary list;
- latest state wins: `Rilevato`, `In quarantena`, `Ripristinato`, `Eliminato`.

No detection heuristics were weakened or broadened in this release.
