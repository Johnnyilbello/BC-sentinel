# BC Sentinel v0.8.0-rc.1 — Consolidation & Release Hardening

This release candidate freezes the v0.8 threat-intelligence architecture for consolidation. It does not add a new protection feature class.

## Consolidation scope

- preserves all native-Windows-accepted v0.8.0-beta.3 threat-channel behavior;
- adds a dedicated release-candidate acceptance gate;
- verifies semantic ordering `0.8.0-beta.3 < 0.8.0-rc.1 < 0.8.0`;
- requires Beta1, Beta2 and Beta3 threat-channel regressions to remain green;
- audits runtime/tool source trees for private signing-key implementation markers;
- keeps remote retrieval non-activating (`auto_stage=false`, `auto_activate=false`);
- keeps signed reputation advisory-only;
- keeps deterministic local protection independent of cloud availability;
- makes the build success banner version-neutral so release tooling no longer reports the historical v0.7 label.

## Release policy

The RC is not considered frozen until native Windows acceptance passes with zero critical failures. The production application update channel remains signature-ready but local developer upgrade/repair continues to be supported until external release-signing operations are established.
