# BC Sentinel v0.1.7 — Release Polish

## UI / UX
- unified sidebar navigation styling;
- Settings now uses the same interaction language as the rest of the sidebar;
- larger, more consistent navigation glyphs and spacing;
- footer version label no longer clips at normal laptop heights;
- dashboard geometry tightened for 1366×768-class displays;
- improved compact behavior for narrower windows;
- tables remain readable when the window is resized;
- explicit Qt high-DPI scale rounding policy for predictable 125% / 150% Windows scaling;
- minimum geometry reduced to remain usable on 1366×768-class displays under DPI scaling;
- Settings uses the same sidebar button component, states and hover behavior as every other section.

## Persistence
- last completed scan is now stored in SQLite;
- dashboard shows `Mai` before the first scan and the last completion timestamp afterwards;
- scan kind, number of files, number of detections and cancellation status are persisted.

## Validation
- end-to-end harmless EICAR test covers:
  scanner → CRITICAL 100/100 → quarantine → restore → history state sync.
- static backend and ransomware tests remain unchanged.

This is intended to be the final polish release before producing the first distributable Windows build.
