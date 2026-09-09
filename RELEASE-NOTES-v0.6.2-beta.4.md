# BC Sentinel v0.6.2-beta.4 — Release Notes

## Elevated Broker Token Classification Fix

This release fixes the last native Windows blocker observed in the one-action UAC broker acceptance.

### Fixed

- An actually elevated `BC-Sentinel-Broker.exe` could be classified as non-admin by the Protection Service even though its own Windows token was elevated/high-integrity.
- Named-pipe impersonation remains the primary source of peer identity.
- When the impersonation token under-reports administrator membership, the service now checks the primary token of the exact client PID returned by `GetNamedPipeClientProcessId`.
- The process-token admin result is accepted only when SID, session and PID match the impersonated peer identity. Any mismatch remains non-admin.
- Added explicit `TokenGroups` evaluation for BUILTIN\Administrators: the group must be enabled and must not be `SE_GROUP_USE_FOR_DENY_ONLY`, preserving correct behavior for UAC-filtered standard tokens.

### Security properties preserved

- No JSON-supplied PID/SID/admin flag is trusted.
- No generic privileged command surface was added.
- Ticket TTL, anti-replay, session binding and requester-result binding are unchanged.
- Standard filtered administrator tokens remain non-admin until the broker is actually elevated through UAC.

### Regression coverage

- Elevated process-token correction requires same identity.
- Cross-identity process token cannot upgrade privileges.
- Full development suite passes; native Windows broker acceptance remains the release gate.
