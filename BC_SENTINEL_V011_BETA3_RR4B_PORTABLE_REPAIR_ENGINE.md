# BC Sentinel v0.11.0-beta.3 — RR-4B Portable Repair Engine

## Goal
Package the accepted RR-4A reversible transaction semantics into a portable Rescue executable without widening mutation authority.

RR-4B remains an offline-recovery checkpoint. It is not a live-host remediation agent and it does not certify recovery.

## Portable workflow
1. `plan`: consume an explicitly approved operations file and produce a plan bound to the validated offline Windows target.
2. `confirmation`: surface the exact plan-hash-bound operator token.
3. `execute`: require that exact token, verify pre-state and replacement provenance, create/verify rollback backup, then perform the atomic replacement and verify post-state.
4. `rollback`: preflight every current post-repair hash and every backup hash before restoring anything; if any state changed unexpectedly, refuse before mutation.

## Safety boundary
RR-4B does not enable:
- live-host repair;
- automatic repair;
- heuristic-only repair;
- arbitrary shell/script/command execution;
- registry hive mutation;
- boot/BCD/firmware mutation;
- disk format/partition mutation;
- service/driver installation;
- process kill or host isolation;
- recovery certification.

Replacement sources must remain outside the offline Windows target. Rollback artifacts must remain outside the target. Existing RR-4A path traversal, symlink/reparse and identity-critical target refusals remain authoritative.

## Portable artifact
PyInstaller `onedir` artifact:

`BC-Sentinel-Rescue-Repair-Portable.exe`

The build emits `repair-portable-integrity.json` containing the executable SHA-256 and explicit negative capability flags.

## Acceptance
RR-4B is accepted only if a normal non-elevated Windows run proves all of the following on harmless synthetic fixtures:
- RR-0 through RR-4B regression tests pass;
- deterministic acceptance gates RR-0 through RR-4B pass;
- portable build and provenance check pass;
- built executable creates a valid plan;
- wrong confirmation produces zero mutation;
- exact confirmation applies the verified replacement;
- rollback preflight verifies post-state and backup provenance;
- manual rollback restores the original hash;
- an out-of-band post-repair target change causes rollback refusal before any mutation;
- no Windows service is registered;
- B2 Protection Service/realtime/EDR protected sources remain byte-identical.

## Logging
Failure output must identify the exact gate stage (`preflight`, `pytest`, `acceptance-*`, `build`, `provenance`, `live-plan`, `live-confirmation`, `live-execute`, `live-rollback`, `live-tamper-guard`, `protected-source`) and its reason.

## Transition
Passing RR-4B proves portable, explicitly authorized, reversible offline file replacement. It does **not** authorize broad real-machine remediation. Any later expansion of allowed repair primitives must be separately gated and must preserve rollback, provenance and fail-closed semantics.
