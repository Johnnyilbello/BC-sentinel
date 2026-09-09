# BC Sentinel v0.3.0 Beta — Reputation & Network

## Scan cancellation hardening
`Annulla scansione` is now cooperative throughout the scan lifecycle:
- directory enumeration checks cancellation;
- filename enumeration checks cancellation;
- SHA-256/SHA-1 hashing checks cancellation every chunk;
- entropy/content phases check cancellation;
- no `QThread.terminate()` is used;
- the UI immediately acknowledges the request and the worker exits safely.

## Local reputation
New privacy-first reputation engine:
- local allowlist trust;
- Authenticode status on Windows when useful;
- publisher subject where Windows exposes it;
- path/mtime/size cache avoids repeated signature checks;
- invalid signatures add contextual risk;
- unsigned executables add only a small risk delta;
- no file hash or metadata is uploaded to a cloud service.

## Network telemetry
New read-only user-space monitor:
- PID/process → local endpoint → remote IP/port → protocol;
- new network events appear in Activity;
- process/network evidence enters behavioral correlation;
- conservative repeated-endpoint and script-interpreter network heuristics;
- no automatic network blocking in v0.3 Beta;
- no Windows Firewall rules are modified.

## Privacy controls
Settings now include:
- Telemetria di rete ON/OFF;
- Reputazione locale / Authenticode ON/OFF.

Both are local and independently disableable.
