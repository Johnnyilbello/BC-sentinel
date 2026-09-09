# BC Sentinel v0.6.2-beta.1 — Development & Security Report

## Baseline

Source baseline: Windows-accepted/frozen v0.6.1-beta.5 Protection Service + Tamper Resistance.

## Security design

The privileged broker is capability-oriented rather than command-oriented. A standard client cannot ask the elevated process to execute an arbitrary command. The service first validates one of its existing privileged protocol operations, stores that operation/payload server-side, and returns only an opaque ticket. UAC elevates a separate broker executable that presents the ticket back to the service. The service validates administrator identity from the Windows transport before consuming it.

Ticket properties:

- 60-second TTL;
- cryptographically random opaque identifier;
- requester SID/session/PID binding;
- same-session elevated consumption;
- atomic one-time use;
- result bound back to requester SID/session/PID;
- bounded per-user/global pending ticket counts;
- replay/cross-session rejection;
- HMAC-chain broker audit events.

The build keeps `BC-Sentinel-Broker.exe` inside the immutable Program Files tree so the existing v0.6.1 HMAC-sealed SHA-256 manifest protects it.

## Update/repair design

The updater does not download code and the broker does not accept arbitrary update paths. The maintenance transaction accepts a local built Protection Service tree only after full manifest verification. The currently installed tree must already authenticate with the machine integrity key. Version comparison blocks downgrades; repair requires equal versions. Apply creates a protected backup and signed journal before replacement. The maintenance script re-applies ACLs, migrates config, seals the new manifest, pipe-selftests and restarts the existing SCM service. Failure routes to rollback.

The legacy unversioned manifest migration accepts only the already authenticated v0.6.1-beta.5 baseline; later manifests are explicitly versioned.

## Verification

- Full test suite: 254 PASS / 0 FAIL.
- Python compileall: PASS.
- New tests cover nested-payload validation, non-admin preparation, elevated same-session execution, replay rejection, cross-session rejection, requester-PID result isolation, ticket expiry, broker argument surface, lightweight broker imports, version ordering, anti-downgrade, same-version repair, transaction backup/journal/rollback and update script structure.

## Native acceptance still required

1. Build v0.6.2 service + broker on Windows.
2. Validate update plan against frozen v0.6.1.
3. Apply transactional upgrade.
4. Run Windows acceptance with service live.
5. Run broker acceptance from non-elevated PowerShell and approve one UAC prompt.
6. Run same-version Repair acceptance.
7. Run controlled rollback/fault-injection acceptance.
8. Reboot and verify service/hardening persistence before freeze.
