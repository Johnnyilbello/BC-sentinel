# BC Sentinel v0.4.0 Beta — Reputation + Network Intelligence

## Release goal

Move BC Sentinel from isolated file/process telemetry toward an explainable local model:

`PROCESS → FILE / BEHAVIOR → CONNECTION → REPUTATION → CORRELATED RISK`

v0.4 remains observation-first. It does not install a WFP filter, block network traffic, terminate processes from network-only heuristics, or enable a cloud reputation provider.

## File reputation

- Added device-local SHA-256 first-seen tracking.
- Added distinct-path prevalence without incrementing on every warm scan.
- Expanded Authenticode context with publisher, issuer, thumbprint, certificate validity, timestamp signer and status message.
- Preserved the rule that publisher allowlisting is trusted only after a `Valid` Authenticode result.
- Kept deterministic detections stronger than trust/reputation context.
- Avoided reintroducing SQLite write amplification during repeated scans.

## Network intelligence

- Added `sentinel/network_intelligence.py`.
- Added local IP/domain normalization and endpoint classification.
- Private, loopback and link-local endpoints are context, not suspicious by themselves.
- Added local endpoint verdicts: unknown / trusted / suspicious / malicious.
- Added endpoint first-seen, connection prevalence and process prevalence.
- Added explainable context for high-risk interpreters and selected Internet-facing administrative ports.
- Added false-positive controls for browsers, launchers, sync clients and common developer tools.
- Generic outbound HTTPS activity is not a detection signal by itself.

## Process → connection attribution

Network events can now carry, when available:

- PID / PPID;
- process name and executable path;
- process create time;
- command line;
- process SHA-256;
- Authenticode status;
- signer;
- remote IP / port / protocol / state;
- endpoint reputation metadata.

Identity enrichment stays outside the collector callback path.

## Telemetry Service

- Added privileged-service network collection.
- Network collection is opt-in after each service restart.
- The authenticated UI can enable/disable only this telemetry collector; no shell/exec/delete/terminate control was added.
- If service collection is active, the UI stops its local network collector to avoid duplicates.
- If the service is unavailable, psutil local fallback remains available.
- Service network events are enriched in the poller worker before reaching the Qt UI thread.
- Service telemetry persistence is batched into a single SQLite transaction per received batch.

## Privacy

No external threat-intelligence provider is enabled in v0.4.

An optional provider interface exists and receives SHA-256(normalized indicator) rather than the raw IP/domain. This is data minimization / pseudonymization, **not anonymity**: IP hashes can be enumerated. Production external intelligence remains blocked on a privacy/security review; signed local feeds are preferred where practical.

BC Sentinel does not perform reverse-DNS requests merely to decorate telemetry.

## Database

Added/migrated:

- richer `file_reputation` certificate columns;
- `file_observations`;
- `endpoint_reputation`;
- `network_endpoint_observations`;
- richer `network_events` process/reputation columns;
- batched service telemetry persistence.

Migrations remain additive for v0.3.1 databases.

## UI

- Protection page now exposes Network Intelligence and File Reputation state.
- Settings copy reflects service/fallback behavior and local reputation scope.
- Activity details show endpoint class/verdict/first-seen/prevalence plus process signature context.
- Threat details show file first-seen/prevalence and richer Authenticode metadata.

## Validation

- `python -m pytest -q` → **152 passed**.
- `python -m compileall -q sentinel app tools` → PASS.
- 5,000-file security benchmark: cold ~3,338 files/s; warm ~4,312 files/s; 4,950 warm hash-cache hits.
- 5,000-event local network-intelligence benchmark: ~1,067 events/s; all 5,000 events persisted.
- Updated Windows acceptance harness adds a harmless localhost TCP process-attribution probe.

The current container cannot certify native Windows ETW/watchdog/AuthentiCode/psutil ownership behavior. Run `python -m tools.windows_acceptance` on the target Windows machine before freezing v0.4.

## Not included

- WFP filtering or network blocking;
- DNS/DoH inspection;
- cloud endpoint reputation provider;
- automated process termination from network telemetry;
- kernel/minifilter components;
- production tamper resistance;
- signed updater/rule channel.

These remain later roadmap items.
