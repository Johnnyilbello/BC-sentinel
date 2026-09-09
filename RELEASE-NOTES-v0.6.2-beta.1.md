# BC Sentinel v0.6.2-beta.1 — Release Notes

## Scope

This beta advances the frozen v0.6.1 Windows Protection Service with a least-privilege UAC action broker and a transactional service upgrade/repair foundation.

## Privileged Action Broker

- `prepare_privileged_action` is available to an authenticated local standard-user client.
- The Protection Service validates the exact target privileged operation and nested payload before issuing a ticket.
- Tickets use cryptographically random identifiers, expire quickly, are single-use, and are bound to requester SID, Windows session and requester PID.
- `BC-Sentinel-Broker.exe` is launched via UAC and receives only `--ticket <opaque-id>`.
- Broker execution still requires a transport-authenticated elevated administrator token.
- Cross-session execution and replay are rejected.
- Results are retained briefly and can be retrieved only by the original requester identity/process.
- Broker lifecycle events are appended to the protected HMAC audit chain.
- Service status exposes only aggregate broker counters, never active ticket identifiers.
- The broker client imports only lightweight protocol/constants modules, not the Protection Service runtime.

## Upgrade / Repair

- Integrity manifests now include `product_version`.
- Current protected installation must authenticate successfully before an update plan is accepted.
- Upgrade mode rejects same-version and older builds.
- Repair mode accepts only the exact current version.
- Source tree is fully SHA-256 verified before staging.
- Existing install tree is backed up before replacement.
- Update transaction state is stored in an HMAC-authenticated journal.
- Failed apply/post-check can restore the backed-up install tree.
- `AGGIORNA-RIPARA-SERVIZIO-PROTEZIONE.ps1` performs stop → transactional apply → ACL hardening → config migration → integrity seal → pipe self-test → start, with rollback on failure.

## Acceptance tooling

- `tools.broker_acceptance`: must be run from non-elevated PowerShell and validates the real standard-user → UAC → broker → service path with an idempotent network-state operation.
- `tools.update_acceptance`: side-effect-free authenticated update/repair plan validation.
- Windows acceptance now includes v0.6.2 broker/update foundation and live broker deployment gates.

## Development verification

- 254/254 tests PASS.
- `compileall` PASS.
- No generic shell/command execution surface in broker/update Python modules.

## Not yet frozen

Native Windows build, transactional upgrade, standard-user UAC acceptance, repair and rollback fault-injection are required before v0.6.2 can be frozen.
