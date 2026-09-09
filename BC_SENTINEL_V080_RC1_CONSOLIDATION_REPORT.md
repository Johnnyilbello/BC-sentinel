# BC Sentinel v0.8.0-rc.1 Consolidation Report

## Goal

Close the v0.8 Signed Threat Intelligence & Secure Update Channel macro-phase without introducing a new detection/enforcement feature surface.

## Frozen security invariants

- threat packages are declarative and cannot execute arbitrary code;
- Ed25519 content/index trust remains separated from application release signing;
- keysets and remote indexes retain independent anti-rollback high-water state;
- revoked signers cannot validate new packages;
- signed reputation remains advisory-only;
- remote retrieval requires HTTPS, exact host policy and certificate pinning;
- retrieval never implies staging or activation;
- active verified content is retained during signer-revocation replacement handling;
- activation recovery permits only complete old or complete new content state;
- core deterministic protection remains local-first and cloud-independent.

## RC gates

The RC acceptance requires all v0.8 Beta1→Beta3 threat gates, release/version consistency, required documentation, runtime private-key marker audit and native service policy checks. Native Windows aggregate acceptance remains mandatory before release freeze.
