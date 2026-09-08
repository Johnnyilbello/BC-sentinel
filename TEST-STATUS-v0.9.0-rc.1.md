# BC Sentinel v0.9.0-rc.1 — Test Status

## Current authoritative status — 8 September 2026

The earlier 7 September 482-test freeze claim in this file is **superseded** by the later security checkpoints.

Checkpoint 4 is the current source-of-record:

- complete regression: **578 passed, zero skipped**;
- targeted Authenticode/reputation invocation tests: 26 passed;
- native Authenticode foundation sub-gate: PASS;
- local RC acceptance: PASS;
- fresh Protection Service and UAC Broker builds: PASS;
- isolated pipe self-test: PASS;
- compileall: PASS;
- artifact integrity: 169 files verified.

## Native freeze status

**v0.9.0-rc.1 is NOT frozen.** The following current-build gates remain OPEN / DEFERRED:

- elevated Windows foundation/ETW;
- live Protection Service;
- UAC broker path;
- upgrade/repair on the checkpoint-4 build;
- reboot persistence;
- aggregate native benchmarking/freeze evidence.

Historical acceptance of an older RC artifact is not acceptance of the later checkpoint-4 artifact. Development may proceed to v0.10, but these gates must not be recorded as PASS without new evidence.

## Regression obligations retained

The v0.9 Beta1→Beta3 safety model, false-positive controls, updater/quarantine/YARA hardening and checkpoint-4 Authenticode corrections remain mandatory regression requirements for later development.
