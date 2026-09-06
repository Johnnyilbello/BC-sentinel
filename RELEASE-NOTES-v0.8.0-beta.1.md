# BC Sentinel v0.8.0-beta.1 — Signed Threat Intelligence & Secure Update Channel

## Scope

This release starts the v0.8 macro-phase without weakening any v0.7 firewall, Web Protection, Threat Decision, quarantine, UAC broker or update/repair invariant already accepted on native Windows.

## Signed threat packages

- New `bcsentinel.threat-package.v1` Ed25519-signed declarative package format.
- Separate pinned threat-content public trust anchor; private signing material is not shipped.
- Bounded components: IOC, YARA and advisory behavioral metadata.
- Canonical JSON signature verification, validity window, minimum-product version and per-component SHA-256 provenance.
- Sequence high-water anti-rollback and sequence-reuse protection.
- Staging validates package structure and, on the production dependency set, compiles every YARA rule before activation.
- Atomic active content publication with machine-HMAC authenticated state and transparency log.
- Last-known-good rollback is the only lower-sequence activation path; arbitrary downgrade remains rejected.
- Threat-package IOC overlay is separate from the legacy signed IOC feed but participates in the same deterministic scanner/network/web matching path with `source=threat_package` provenance.
- YARA engine hot-reloads the machine-owned active signed-rule directory; a failed refresh keeps the last compiled ruleset in memory.
- Behavioral package data is advisory-only in beta.1: the package schema cannot contain commands/scripts/actions and does not execute arbitrary code.

## Secure application update channel foundation

- New `bcsentinel.release-envelope.v1` Ed25519 publisher envelope with a separate application-release trust anchor.
- Exact relative file-set, SHA-256 and size verification.
- Rejects missing, extra, modified, symlink/reparse and path-traversal content.
- The current local developer `BUILD -> Upgrade/Repair` path remains compatible in beta.1 and does not require a publisher signature yet.
- The production channel format is ready for later `signature-required` enforcement once external release signing exists.

## Privileged boundary

- Read-only package validation/status/history is available through authenticated local IPC.
- Stage, activate, install and LKG rollback are privileged operations.
- Standard-user GUI uses one-action UAC for `stage + activate` installation; no generic elevated shell is introduced.
- Existing rate limiting, requester binding, ticket replay protection and audit chain remain authoritative.

## UI

Settings > Threat Intelligence now exposes the v0.8 package channel, active sequence/high-water/LKG state and signed package installation alongside the legacy IOC feed.

## Safety invariants

- No private signing key in the release.
- No arbitrary package code execution.
- No HTTPS MITM/root CA.
- No heuristic auto-block.
- No global Windows Firewall policy mutation.
- No third-party firewall rule mutation.
- File quarantine/delete still require the existing file verdict/Threat Decision gates.
