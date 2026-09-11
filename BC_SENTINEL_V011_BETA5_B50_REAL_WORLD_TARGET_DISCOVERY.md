# BC Sentinel v0.11.0-beta.5 — B5-0 Real-World Target Discovery

## Purpose
B5-0 is the first field-hardening milestone after the accepted Beta4 Portable Rescue Console. It discovers realistic offline Windows candidates without modifying storage and refuses the currently running Windows system volume as an offline target.

## Frozen predecessor
```text
checkpoint/v011-beta4-b45-pass
823ec10ff20157661e66418ac977c0827a654e29
```

No Beta3/Beta4 checkpoint may move or be rewritten.

## Discovery states
Every considered root receives exactly one state:
- `READY`: complete required Windows markers and RR-6 target validation/fingerprint pass;
- `LOCKED`: a read-only BitLocker/status probe or known Windows lock/not-ready error proves the volume is locked/unavailable;
- `ACCESS_DENIED`: filesystem permission/access denial;
- `INCOMPLETE`: some Windows markers exist but the mandatory RR-6 target contract is incomplete;
- `UNSUPPORTED`: not a Windows candidate, symlink/reparse root, non-directory, or the live `SystemDrive` root;
- `ERROR`: unexpected failure that cannot be safely classified above.

## Safety contract
B5-0 is discovery only.

It MUST NOT:
- unlock BitLocker;
- mount or remount volumes;
- format disks;
- alter partitions;
- write BCD/boot sectors/bootloaders;
- run filesystem repair;
- execute target binaries or load target DLLs;
- install services or drivers;
- require network/cloud services;
- write into discovered target roots.

The BitLocker/CIM probe is informational only. If the provider is unavailable, B5-0 records the provider failure and continues with filesystem classification; it never tries to obtain keys or unlock the volume.

## Live SystemDrive rule
The exact root of Windows `SystemDrive` (for example `C:\`) is always `UNSUPPORTED` with reason `live_system_volume_refused`.

This rule applies only to the live drive root. Explicit offline image/mount directories located below the technician system drive remain eligible for read-only validation.

## Bounded discovery
Hard limits:
- max roots: 128;
- default roots: 64;
- max immediate child probes per explicit root: 128 hard, 32 default;
- BitLocker provider timeout: 0.5–15 seconds, 4 seconds default.

No recursive whole-disk crawl is performed by B5-0. Explicit roots may optionally probe only immediate child directories.

## RR-6 binding
`READY` is not based on naming heuristics. A complete candidate must pass the already accepted RR-6 offline Windows root validator and receives the RR-6 target fingerprint.

## Observability
Result records expose:
- normalized root;
- discovery source;
- state and exact reason;
- marker inventory;
- target fingerprint when READY;
- BitLocker provider status/exit code/timing when available;
- per-candidate elapsed time;
- session and correlation IDs;
- global counts and limits.

## Acceptance
B5-0 may be frozen only when all of the following pass on Windows:
- complete Beta3 + Beta4 + B5-0 pytest regression, expected **212 tests**;
- every predecessor deterministic acceptance;
- deterministic B5-0 acceptance;
- two READY synthetic Windows installations with independent RR-6 fingerprints;
- INCOMPLETE and UNSUPPORTED classification;
- simulated BitLocker LOCKED refusal;
- ACCESS_DENIED and Windows lock-error classification;
- bounded/deduplicated deterministic discovery;
- live fixture target byte-identical before/after;
- real Windows volume enumeration bounded to the requested maximum;
- exact live SystemDrive refusal as `UNSUPPORTED / live_system_volume_refused`;
- no unlock/mount/write/service/driver/network/cloud behavior;
- protected B2 service/realtime/EDR sources unchanged;
- final core and bootstrap PASS.

No failure threshold or predecessor acceptance may be relaxed to obtain PASS.
