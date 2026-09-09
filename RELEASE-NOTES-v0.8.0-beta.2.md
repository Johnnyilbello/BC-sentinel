# BC Sentinel v0.8.0-beta.2

## Trust Key Lifecycle, Signed Reputation, Recovery & Secure Retrieval Foundation

This beta extends the v0.8 signed threat-intelligence channel without weakening the v0.7.x endpoint/firewall/web protections or the v0.8.0-beta.1 staged package model.

### Added

- root-pinned Ed25519 threat-content keyset format (`bcsentinel.threat-keyset.v1`);
- signed content-key rotation with independent `key_id` identities;
- explicit key revocation and keyset high-water anti-rollback;
- backward-compatible `legacy-beta1` content-key handling unless explicitly revoked by a later root-signed keyset;
- threat packages can identify their signing key through `signing_key_id`;
- signed **domain/network reputation** component with bounded entries, confidence, expiry and provenance;
- signed reputation remains advisory and does not become an automatic firewall/quarantine action;
- authenticated activation recovery journal for crash/restart consistency;
- incomplete content publication is rolled back to the previously committed active package;
- a crash after committed state is recognized as completed rather than incorrectly rolled back;
- HTTPS-only remote retrieval foundation with exact-host allowlist, TCP/443 restriction, peer-certificate SHA-256 pinning, bounded response size and optional content SHA-256 verification;
- redirects, URL credentials and unpinned hosts are rejected;
- retrieval is separate from staging/activation (`auto_stage=false`, `auto_activate=false`);
- deterministic local protection remains functional without cloud access (`cloud_required=false`).

### Security invariants

- root key and content keys are separate trust layers;
- private signing keys are not shipped;
- a revoked content key cannot validate new threat packages;
- keyset rollback is not permitted; recovery requires a new, higher-sequence root-signed keyset;
- signed reputation is evidence, not a denylist and not destructive enforcement;
- IOC denylist evidence retains higher enforcement significance than reputation evidence;
- threat packages remain declarative: no arbitrary scripts, shell commands or executable payloads;
- activation remains explicit, protected and reversible through the existing service/UAC architecture;
- secure retrieval never auto-activates downloaded content.

### Acceptance target

Cross-platform development target for the final package:

- full pytest regression PASS;
- `compileall` PASS;
- v0.8.0-beta.1 threat-package acceptance PASS;
- new v0.8.0-beta.2 trust/reputation/recovery/retrieval acceptance PASS.

Native Windows freeze additionally requires the installed Protection Service live gate and aggregate `tools.windows_acceptance --service-live` with zero critical failures.
