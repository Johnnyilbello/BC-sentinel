# BC Sentinel v0.8.0-beta.1 — Development Report

## Objective
Establish a signed, versioned and reversible security-content supply chain without turning content packages into executable code and without breaking the accepted v0.7 protection boundaries.

## Implemented
- `sentinel/threat_packages.py`: Ed25519 verification, bounded IOC/YARA/behavior components, staging, HMAC state, transparency log, anti-rollback and LKG rollback.
- Database threat-package IOC overlay integrated into existing signed IOC lookup paths.
- `YaraEngine` machine-owned signed rule hot reload with last-compiled fail-safe behavior.
- Protection Service IPC: read-only validation/status/history plus privileged stage/install/activate/rollback operations.
- Standard-user one-action UAC install path.
- `sentinel/release_channel.py`: separate publisher release-envelope verification and exact-tree integrity validation.
- Settings UI status/install controls.
- Dedicated `tools.threat_package_acceptance` and Windows aggregate gates.

## Deliberate beta.1 limits
- behavior package content is validated/published but not yet used as enforcement policy;
- no remote download transport is introduced;
- local developer upgrade remains unsigned for iteration compatibility;
- production update signature enforcement waits for an external/offline signing pipeline and key-management process.
