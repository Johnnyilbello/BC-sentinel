# BC Sentinel v0.8.0-beta.3

## Signed Remote Threat Index, Controlled Retrieval & Revocation Operations

This beta operationalizes the v0.8 secure threat channel while preserving the v0.8.0-beta.2 key lifecycle, signed reputation, activation recovery and HTTPS-pinned retrieval invariants.

### Added

- separate Ed25519-pinned `bcsentinel.threat-index.v1` remote index;
- signed index metadata for package identity, sequence, version, SHA-256, exact byte size, HTTPS URL, signing key, components and minimum BC Sentinel version;
- HMAC-authenticated index state with independent sequence high-water anti-rollback and same-sequence payload-reuse protection;
- candidate selection skips revoked/unavailable signing keys and packages that are not newer or product-compatible;
- `ThreatContentCache` with SHA-256 content-addressed filenames, atomic writes, reparse checks, bounded entry count and bounded disk usage;
- `ThreatCheckScheduler` with authenticated state, minimum one-hour cadence, bounded retry backoff and no activation side effects;
- `ThreatRemoteCoordinator` that performs signed-index retrieval -> candidate retrieval -> envelope hash/size verification -> package signature/key verification -> safe cache only;
- remote retrieval explicitly remains `auto_stage=false` and `auto_activate=false`;
- Protection Service exposes read-only signed-index validation plus remote-index/cache/scheduler/channel posture;
- active packages whose signing key becomes revoked enter `critical_replacement_required` state while the last verified content remains readable and active;
- revocation policy is fail-closed for new package validation but performs no destructive automatic deletion of currently active content;
- activation fault-injection points now cover package promotion, journal preparation, IOC/reputation/YARA/behavior publication, publication journal commit, state commit and journal clear;
- acceptance verifies every simulated crash resolves to either the complete previous package or the complete new package, never mixed content.

### Security invariants

- the signed remote index has a trust anchor separate from threat-content signing keys;
- index rollback is rejected independently of threat-package rollback protections;
- index metadata cannot replace the inner threat-package Ed25519 signature check;
- retrieved package bytes must match the signed index SHA-256 and exact size before parsing/verification;
- package signing-key identity and component metadata must match the signed index;
- revoked signing keys are skipped for candidate selection and rejected by package verification;
- remote retrieval does not imply staging or activation;
- scheduler state cannot reduce checks below the bounded minimum interval;
- cached content is data-only and is never executed;
- a revoked active signer does not trigger automatic deletion, firewall mutation or fail-open behavior;
- deterministic protection remains available offline (`cloud_required=false`).

### Acceptance target

Development package must pass:

- full pytest regression;
- `compileall`;
- v0.8.0-beta.1 threat-package acceptance;
- v0.8.0-beta.2 trust/reputation/recovery/retrieval acceptance;
- v0.8.0-beta.3 signed-index/controlled-retrieval/fault-matrix acceptance.

Native Windows freeze additionally requires installed Protection Service validation, YARA production dependency coverage and aggregate `tools.windows_acceptance --service-live` with zero critical failures.
