# BC Sentinel v0.4.1 Beta — Behavioral Correlation Engine 2.0

## Release focus

v0.4.1 turns the v0.4 Reputation + Network Intelligence telemetry into a more coherent behavioral timeline. The release is intentionally not a "wow feature" release: it improves sequence/context reasoning, false-positive resistance, explainability and packaging reliability without adding autonomous response actions.

## Main changes

- 45-second sliding behavioral correlation window.
- Parent/child/ancestor correlation across PID boundaries.
- Ordered sequence detection for:
  - encoded script → network;
  - downloader → file write;
  - written payload → execution;
  - downloader → temporary payload execution;
  - network → persistence.
- PID-less persistence events can be linked when their value directly references a recently observed executable.
- Evidence families use strongest-signal wins with diminishing convergence returns.
- Browser/developer/high-volume network clients retain conservative false-positive gates.
- Correlation results now expose:
  - incident ID;
  - total score;
  - severity;
  - confidence;
  - behavioral stages;
  - evidence families;
  - bounded human-readable event sequence.
- Local persistence events now pass through the same correlation pipeline used by service telemetry.
- Correlation history access is protected by locks for concurrent telemetry callbacks.
- `requirements.txt` now installs `pywintrace` and `pywin32` automatically on Windows.
- Windows acceptance adds a side-effect-free Behavioral Correlation Engine 2.0 probe.

## Safety boundary

v0.4.1 remains advisory/contextual at this layer. It does not automatically terminate processes, block network traffic, delete files or quarantine based solely on behavioral correlation. Response authority remains deferred to the future protected Windows Service architecture.

## Validation in development container

- Baseline v0.4.0 tests: **152/152 PASS**.
- Final v0.4.1 tests: **164/164 PASS**.
- `compileall`: **PASS**.
- Synthetic Correlation Engine benchmark: **10,000 events / 200 processes**.
- Throughput after thread-safety locking: **~2,133 events/s**.

## Windows freeze gate

Run from an elevated PowerShell in the project directory:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --output acceptance-v041-final.json
```

The release is frozen only when `passed` is `true` and `critical_failures` is empty on the target Windows machine.

## Roadmap

Next major phase after v0.4.1 acceptance: **v0.5 — Windows Protection Service & Tamper Resistance**.

The macOS path remains in the roadmap:

- v0.8 — macOS Native Protection Foundation;
- v0.9 — signed/notarized macOS `.pkg`/`.dmg` installer and Windows production installer.
