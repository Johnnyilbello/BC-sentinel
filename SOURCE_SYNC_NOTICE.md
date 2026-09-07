# Source synchronization status

The repository now records the frozen `v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening` baseline and its verified release metadata.

## Navigable source synchronized

The repository intentionally exposes the security-relevant development deltas and acceptance evidence rather than claiming that every file from the complete release archive has been materialized individually through the connected GitHub integration.

Tracked v0.9 material includes the Beta3 advanced-antimalware delta, RC1 consolidation/false-positive acceptance, package/runtime versioning, roadmap/status/release evidence and Windows acceptance documentation.

## Complete source snapshot

The complete source-of-record for the accepted RC1 is:

`BC_Sentinel_v0_9_0_RC1_Antimalware_Consolidation_Native_Hardening.zip`

SHA-256:

`8a4a2c3e1cc7c9c411d7e25c189d016b29994311a4d991caba30dfa5bc23b350`

Target-Windows validation completed on 2026-09-07 with 482/482 Python tests and all RC1 foundation/build/upgrade/live/repair/hardening/post-reboot gates passing.

Generated caches, local virtual environments and acceptance output JSON files are not source-of-record and are not committed.

The next development line is `v0.10.0-beta.1`; the RC1 source snapshot and its safety gates remain frozen regression requirements.
