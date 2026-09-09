# BC Sentinel v0.2.2-beta — Detection Hardening

## Behavioral correlation
New sliding-window correlation engine combines defensive telemetry instead of
judging isolated signals independently.

Examples:
- Office → PowerShell;
- browser → script interpreter;
- encoded PowerShell;
- downloader-like command lines;
- execution from Temp;
- recent file write → process launch;
- persistence events tied to risky paths/interpreters;
- bursts of writes/renames/deletes by the same PID.

Correlation only adds context. It does not directly kill processes, delete files
or quarantine content.

## Event deduplication
Identical telemetry events are suppressed for a short TTL before they reach the
activity journal, reducing duplicate ETW/psutil/watchdog noise.

## Persistence scoring
Run/RunOnce/Startup/Task changes now receive contextual scoring:
- ordinary startup changes stay low/moderate;
- Temp paths add risk;
- interpreters/loaders add risk;
- encoded PowerShell adds further risk.

No legitimate startup entry is automatically removed.

## Activity
Activity now displays the base event score plus correlation context and can show:
- process;
- PID;
- process tree;
- correlation risk delta;
- correlation confidence.

## Architecture
Correlation is a separate `sentinel/correlation_engine.py` module so it can
later move into the native Rust/C++ core without coupling it to the UI.
