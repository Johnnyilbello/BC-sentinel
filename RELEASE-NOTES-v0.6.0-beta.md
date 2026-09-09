# BC Sentinel v0.6.0 Beta — Release Notes

## Headline

BC Sentinel now has a real always-on Windows protection-service architecture. The former localhost TCP Telemetry Service control surface has been retired in favor of an ACL-protected Windows Named Pipe and strict authenticated command protocol.

## Security architecture

- Service: `BCSentinelProtection`
- Pipe: `\\.\pipe\BCSentinelProtection-v1`
- Standard GUI: monitoring/control surface with local fallback only if service unavailable
- Privileged service: realtime, process, ETW, persistence, network, behavioral correlation, incidents and guarded response
- Privileged commands require Windows administrator client context plus installation-token verification
- JSON only; no pickle or arbitrary method dispatch

## Safety

No kernel driver, firewall filtering, forced-kill escalation or autonomous heuristic remediation was added. Microsoft Defender should remain enabled during beta testing.

## Verification

Development environment:

- 197/197 tests PASS
- compileall PASS
- 21 v0.6-specific tests

Native Windows service-live acceptance remains the release freeze gate.
