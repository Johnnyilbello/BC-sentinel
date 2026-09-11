# BC Sentinel — Roadmap v0.11.0-beta.4 Rescue Console

## Frozen predecessor
Beta4 starts only from the accepted Beta3 Rescue & Recovery checkpoint:

```text
checkpoint/v011-beta3-rr6-pass
e03482f4216c4cd20ede1e16d9a4c4b5b07668bc
```

RR-0 through RR-6 remain immutable predecessors. Beta4 must not weaken or bypass any accepted safety gate.

## Beta4 goal
Turn the independently accepted Rescue components into one coherent operator workflow for servicing an offline or compromised Windows installation, while preserving explicit operator control and all Beta3 trust boundaries.

Beta4 is orchestration, not a grant of new mutation authority.

## B4-0 — Rescue Console Orchestrator Foundation — accepted
Authoritative Windows acceptance: **144 tests PASS**, deterministic predecessor gates PASS, target unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b40-pass
3bb5d0553397cccefba31eac70c09a99305e2492
```

## B4-1 — Evidence Inventory + Guided Scan — accepted
Authoritative Windows acceptance: **157 tests PASS**, fresh RR-3 scan/trusted reuse/tamper refusal PASS, no automatic repair/quarantine, target unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b41-pass
5049b2246df692c0f417131af44353cc234e1f95
```

## B4-2 — Guided Repair Handoff — accepted
Authoritative Windows acceptance: **167 tests PASS**, trusted scan + approved operations + plan-bound confirmation PASS, frozen RR-4B execute/rollback regression PASS, no Console auto-repair, target unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b42-pass
cb6ef6dd65ed9528c4613f896e0c84fde66ffc79
```

## B4-3 — Guided Safe Data Rescue — accepted
Authoritative Windows acceptance: **176 tests PASS**, preview/no-copy, explicit selection, passive rescue, IOC containment and manifest verification PASS, source unchanged, no service, B2 protected sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b43-pass
641472a24d3f41feaf4351d65405c39b09622d67
```

## B4-4 — Integrated Certification + Session Summary — accepted
Accepted boundary:
- Beta4 session continuity is validated before RR-6;
- B4-0 plan, B4-1 trusted RR-3 evidence, optional B4-2 handoff/transaction and optional B4-3 rescue summary/manifest must bind to the same target/session evidence;
- session-continuity failure returns `INDETERMINATE_REFUSED` before RR-6;
- trusted sessions invoke frozen RR-6 unchanged;
- RR-6 outcomes are preserved exactly: `RECOVERED`, `NOT_RECOVERED`, `INDETERMINATE_REFUSED`;
- target remains read-only during certification;
- no repair execution or new mutation authority is added;
- reimage/format is never suppressed when trust cannot be demonstrated.

Authoritative Windows acceptance:
- Beta3 + B4-0..B4-4 regression: **188 tests PASS**;
- clean integrated session -> `RECOVERED` PASS;
- trusted unresolved IOC -> `NOT_RECOVERED` PASS;
- session binding failure -> `INDETERMINATE_REFUSED` before RR-6 PASS;
- RR-6 trust/provenance failure -> `INDETERMINATE_REFUSED` PASS;
- summary/RR-6 hash binding PASS;
- target unchanged, no service, B2 protected sources unchanged;
- final B4-4 core and bootstrap PASS.

Frozen checkpoint:
```text
checkpoint/v011-beta4-b44-pass
0735125b90fbd047907b33da8e8c9928778377f1
```

## B4-5 — Portable Rescue Console — current
Purpose: package the accepted B4-0 through B4-4 workflow as one standard-user portable CLI without installer, Windows service or driver requirements.

Required boundaries:
- one portable entrypoint may dispatch only to accepted Beta4 stages;
- allowed command surface is `plan`, `scan`, `repair-handoff`, `data-rescue`, `certify`, plus read-only `status`;
- there is no `repair-execute` command in the Console;
- B4-2 remains a repair handoff only; actual repair execution/rollback stays in frozen RR-4B semantics outside the Console surface;
- `data-rescue` keeps B4-3 explicit execution requirements and RR-5 containment semantics;
- `certify` preserves all B4-4/RR-6 final outcomes exactly;
- package is PyInstaller `onedir`, standard-user runnable, no installer/service/driver;
- no network/cloud dependency is introduced;
- build uses short isolated work/TEMP paths, up to three attempts and full PyInstaller diagnostics;
- built EXE SHA-256 must match its integrity manifest;
- built `status` must expose the accepted command/safety contract;
- built artifact must refuse `repair-execute`;
- built artifact must successfully run a clean `plan` -> `scan` -> `certify` flow on a synthetic offline target;
- built artifact must leave the synthetic target byte-identical;
- no Windows service may be registered;
- protected B2 service/realtime/EDR sources must remain unchanged.

B4-5 Windows acceptance must include:
- Beta3 + B4-0..B4-5 regression, expected **198 tests**;
- all deterministic RR-0..RR-6 and B4-0..B4-5 gates PASS;
- hardened PyInstaller onedir build PASS;
- integrity manifest SHA-256 == built EXE SHA-256;
- built `status` PASS;
- built forbidden `repair-execute` refusal PASS;
- built `scan`, `repair-handoff`, `data-rescue`, `certify` subcommands load successfully;
- built clean plan/scan/integrated-certification flow -> `RECOVERED`;
- target unchanged, no service, B2 sources unchanged.

## Beta4 closure condition
Beta4 closes only after B4-5 passes the full Windows built-artifact gate above and the exact accepted B4-5 code is frozen at `checkpoint/v011-beta4-b45-pass`. The checkpoint must never move.

## Logging policy
Every critical failure must expose stage, reason/cause, session/correlation ID when available, target fingerprint when useful, component state, child exit code, relevant counters/timings and normalized paths. Diagnostic/acceptance logs may be verbose; production logs remain structured and bounded.

## Codex reasoning policy
- **Extra High**: orchestration trust boundaries, transaction handoff, certification semantics and any capability that could mutate a target.
- **High**: implementation, tests and packaging after the corresponding boundary is frozen.
- milestone-by-milestone only.
