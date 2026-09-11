# BC Sentinel — Roadmap v0.11.0-beta.3 Rescue & Recovery

## Frozen predecessor
`v0.11.0-beta.2` is accepted and frozen at:

```text
checkpoint/v011-beta2-b2-pass-v6
b943f1ee550ad5c2bee3d8753962d5971c212381
```

Final B2 Windows gate: `BC SENTINEL v0.11.0-beta.2 B2 NONEXEC OBSERVATION V6 - PASS`.

## RR-0 — Architecture & Safety — accepted
RR-0 established the Rescue security contract without adding repair/delete/write execution.

Authoritative FULL Windows evidence:
- 22 RR-0 tests PASS;
- deterministic RR-0 acceptance PASS;
- read-only default enforced;
- destructive actions disabled;
- file delete/process kill/host isolation disabled;
- registry/boot/filesystem writes disabled;
- recovery certification disabled;
- SHA-256 evidence contract enabled;
- workers/inflight bounded;
- compromised Windows limited to evidence acquisition/inspection/export;
- trusted external media/offline image may only plan quarantine/repair, never execute it in RR-0.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-0 ARCHITECTURE & SAFETY - PASS
BC SENTINEL v0.11.0-beta.3 RR-0 BOOTSTRAP - PASS
```

Frozen RR-0 checkpoint:

```text
checkpoint/v011-beta3-rr0-pass
efc78e88e7004ea9c4289c1aab233c92f34f7748
```

## RR-1 — Portable — accepted
RR-1 delivered the first operational Rescue acquisition runtime that runs from a normal folder or trusted external media without installing BC Sentinel.

Authoritative FULL Windows evidence:
- RR-0 + RR-1 regression: **40 tests PASS**;
- deterministic RR-0/RR-1 acceptance: **PASS**;
- portable PyInstaller onedir build: **PASS**;
- portable binary SHA-256 `9deac6fed9dfc27b091f060ffe9887a161fdf31a034d4cb656849e8fe17f34f9`;
- built executable launched successfully as standard user;
- live harmless fixture: `2/2` SHA-256 evidence records;
- target content unchanged;
- no Rescue Windows service registered;
- B2 protected sources unchanged.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-1 PORTABLE - PASS
BC SENTINEL v0.11.0-beta.3 RR-1 BOOTSTRAP - PASS
```

Frozen RR-1 checkpoint:

```text
checkpoint/v011-beta3-rr1-pass
fbf5be7a9c00fb01d36834f431253b7eae7eb1f3
```

## RR-2 — Rescue USB — accepted
RR-2 turns the accepted RR-1 portable runtime into a trusted removable-media rescue workflow without destructive disk preparation.

Authoritative FULL Windows evidence:
- RR-0 + RR-1 + RR-2 regression: **53 tests PASS**;
- deterministic RR-0/RR-1/RR-2 acceptance: **PASS**;
- deliberate payload tamper detected;
- offline Windows candidate discovery read-only;
- live Rescue-media simulation prepared **56 files / 19,470,134 bytes**;
- live post-copy verification **56/56**, zero errors;
- source payload unchanged;
- B2 protected sources unchanged.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-2 RESCUE USB - PASS
BC SENTINEL v0.11.0-beta.3 RR-2 BOOTSTRAP - PASS
```

Frozen RR-2 checkpoint:

```text
checkpoint/v011-beta3-rr2-pass
93c5082a3f9c7691df3e7905c763a129e8586bed
```

Important boundary: RR-2 does **not** claim bootable-media creation. No formatting or boot-chain write capability is enabled.

## RR-3 — Offline Threat Scanner — accepted
RR-3 analyzes an offline Windows installation from trusted Rescue media while keeping the target read-only.

Authoritative FULL Windows evidence:
- RR-0 + RR-1 + RR-2 + RR-3 regression: **75 tests PASS**;
- deterministic RR-0/RR-1/RR-2/RR-3 acceptance: **PASS**;
- deterministic approved SHA-256 IOC detected exactly once and remained review-only;
- startup evidence and double-extension evidence surfaced;
- offline registry hive metadata observed read-only;
- local YARA runtime detected and included in the portable build;
- PyInstaller onedir scanner build: **PASS**;
- scanner binary SHA-256 `02903b8340472b1ab51643d573cc0b522fb4a741592ec3b7a622b08c8618f805`;
- live portable scanner summary: enumerated `4`, hashed `4`, skipped `0`, errors `0`, IOC hits `1`, YARA hits `1`, heuristic review items `2`, registry hives `3`;
- live target remained byte-identical after scan;
- no Rescue scanner Windows service registered;
- B2 Protection Service/realtime/EDR sources remained unchanged.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-3 OFFLINE THREAT SCANNER - PASS
BC SENTINEL v0.11.0-beta.3 RR-3 BOOTSTRAP - PASS
```

Frozen RR-3 checkpoint:

```text
checkpoint/v011-beta3-rr3-pass
58f2767bf8d9460999d8647b07cfc00856355180
```

## RR-4A — Reversible Transaction Core — accepted
RR-4A introduced the first controlled offline mutation primitive, restricted to harmless synthetic Windows fixtures and designed around fail-closed transaction semantics.

Authoritative FULL Windows evidence:
- RR-0 through RR-4A regression: **88 tests PASS**;
- deterministic RR-0/RR-1/RR-2/RR-3/RR-4A acceptance: **PASS**;
- wrong confirmation refused and target unchanged;
- verified rollback backup created before mutation;
- repair applied and verified;
- manual rollback restored original content;
- stale precondition refused and stale target preserved;
- induced partial failure triggered automatic rollback and restored all already-applied operations;
- automatic repair, live-host repair, registry write, boot write and recovery certification remained disabled;
- B2 protected sources remained unchanged.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-4A REVERSIBLE TRANSACTION CORE - PASS
BC SENTINEL v0.11.0-beta.3 RR-4A BOOTSTRAP - PASS
```

Frozen RR-4A checkpoint:

```text
checkpoint/v011-beta3-rr4a-pass
55d7dbbfedce76ea02f42ec0e661c63b8bef9f14
```

## RR-4B — Portable Repair Engine — accepted
RR-4B packages the RR-4A reversible transaction semantics into a portable onedir Rescue repair tool without weakening the safety boundary.

Accepted scope:
- standard-user PyInstaller `onedir` build; no installer/service/driver installation;
- separate `plan`, `execute` and `rollback` phases;
- exact target fingerprint, evidence reference, pre/post SHA-256 and plan SHA-256;
- execute requires exact operator confirmation token bound to the plan hash;
- wrong confirmation produces zero mutation;
- replacement source remains outside the offline target and provenance-verified;
- rollback copy remains outside target and hash-verified before write;
- stale target/replacement change fails closed;
- manual rollback performs a complete preflight of expected post-state and backup hashes before touching any target file;
- changed post-repair state causes rollback refusal before mutation;
- no live-host repair, registry/boot/BCD/firmware mutation, arbitrary command execution or automatic repair;
- no recovery certification; RR-6 owns certification;
- B2 protected sources remain byte-identical.

Authoritative FULL Windows evidence:
- RR-0 through RR-4B regression: **97 tests PASS**;
- deterministic RR-0/RR-1/RR-2/RR-3/RR-4A/RR-4B acceptance: **PASS**;
- RR-4B deterministic checks all PASS, including wrong-confirmation zero mutation, execute/rollback roundtrip and post-repair-change rollback refusal;
- PyInstaller onedir portable repair build: **PASS**;
- portable repair binary SHA-256 `b748d6eae43cfd1152b269de30c152ffda89fdedd20532e1041867ceaaa634a5`;
- live plan SHA-256 `1e2bf6c3ce444c7a441b0d99f14f7fb47c560569c907a9a3d8a492cc90dfc0f3`;
- built EXE live flow: plan PASS, wrong-confirmation zero-mutation PASS, repair PASS, verified manual rollback PASS, changed-post-state rollback refusal PASS;
- no Rescue Repair Windows service registered;
- live-host repair, automatic repair, registry write, boot write and recovery certification remained disabled;
- B2 Protection Service/realtime/EDR protected sources remained unchanged.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-4B PORTABLE REPAIR ENGINE - PASS
BC SENTINEL v0.11.0-beta.3 RR-4B BOOTSTRAP - PASS
```

## RR-5 — Safe Data Rescue — current
Goal: extract user data from compromised/offline Windows into a clean Rescue destination without executing content or silently carrying active threats into the clean environment.

Required first acceptance scope:
- source is a validated offline Windows root and remains read-only;
- destination must be outside the source tree and may not be a symlink/reparse point;
- copy only explicit user-selected data roots/files; no whole-disk blind copy by default;
- bounded file count, total bytes, per-file size and traversal depth;
- never follow symlink/reparse targets;
- calculate SHA-256 before/after copy and require exact equality;
- generate a deterministic rescue manifest with source path, destination path, size, SHA-256 and disposition;
- classify potentially active content by extension/location and isolate it from ordinary rescued documents instead of placing it directly in the clean-data tree;
- executable/script/shortcut content must never be auto-executed or trusted merely because it was copied;
- optional local IOC/YARA checks may mark data for quarantine/review but must not execute source content;
- suspected/active content goes to a clearly separated containment area with metadata, never into normal restored-user-data output;
- destination collisions, unsafe names, path traversal and case-insensitive aliases must fail closed;
- source file changes during extraction must be detected through pre/post hash/stat checks and reported, not silently accepted;
- copy errors are contained per item and surfaced in audit output;
- structured logs include stage/status/reason/source/destination/hash/bytes/duration/session/correlation IDs;
- no delete from source, no repair mutation, no registry/boot writes and no recovery certification;
- preserve RR-0 through RR-4B regression gates and keep B2 protected sources byte-identical.

RR-5 acceptance uses harmless synthetic offline user-data fixtures containing normal documents plus inert executable/script test markers. Real malware samples are not required.

## RR-6 — Integrity Verification & Recovery Certification — future
Goal: multi-signal integrity validation after rescue/repair and explicit refusal to certify recovery when trust cannot be demonstrated.

Formatting/reimaging remains the last-resort recovery option and may never be suppressed when system integrity cannot be demonstrated.

## Safety invariants carried through Beta3
- B2 Protection Service/realtime/EDR sources are not modified by RR-0/RR-1/RR-2/RR-3/RR-4/RR-5 work;
- no single heuristic HIGH;
- no heuristic-only destructive response;
- no automatic process kill or host isolation;
- signed IOC and Web Protection safeguards remain unchanged;
- no HTTPS MITM/root CA/TLS interception;
- no mandatory cloud runtime dependency;
- frozen service performance thresholds `25 / 10 / 250` are not weakened.

## Codex reasoning policy
- **Extra High**: Rescue architecture, trust boundaries, offline/boot parsing, repair transactions, safe data extraction and integrity certification.
- **High**: ordinary implementation/test/integration after the relevant security boundary is frozen.
- milestone-by-milestone only; no future capability may be pulled forward merely to make a demo appear complete.
