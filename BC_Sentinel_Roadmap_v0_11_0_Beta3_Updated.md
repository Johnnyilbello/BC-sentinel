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

Accepted scope:
- validates offline Windows root markers before scanning;
- bounded read-only inspection of executable, driver, script and startup/persistence locations;
- SHA-256 evidence and explicitly approved local hash IOC matching;
- optional local YARA evaluation with no cloud/network dependency;
- registry hive presence/metadata inspection without loading or writing target hives;
- startup, user-temp, LOLBin-name and double-extension evidence surfaced as review-only;
- no target execution, DLL load, shell execution, process kill, delete, quarantine execution, registry/boot write or recovery certification;
- structured audit records and scan output outside the target;
- B2 protected sources remain byte-identical.

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

Frozen RR-3 checkpoint will be created from this accepted source lineage.

## RR-4 — Repair Engine — current
Goal: introduce the first controlled mutation capability for **offline** recovery while making every change reversible, provenance-backed and explicitly operator-authorized.

Required first acceptance scope:
- RR-4 operates only against a validated offline Windows root; no live-host repair in the first checkpoint;
- no repair may start from heuristic-only evidence or a single weak signal;
- every repair plan contains target fingerprint, source finding/evidence references, exact operation, expected pre-state SHA-256, intended post-state, rollback strategy and plan hash;
- plan generation and execution are separate phases;
- execution requires explicit operator confirmation bound to the exact plan hash; stale or modified plans must fail closed;
- every target file mutation requires a verified rollback copy outside the target before the first write;
- precondition hashes must match immediately before mutation; TOCTOU/stale-state mismatch aborts the transaction;
- path traversal, symlink/reparse-point escape, cross-volume aliasing and filesystem-root targets must be refused;
- initial mutation primitives are allowlisted and minimal; no arbitrary shell command, script execution, generic command dispatch or arbitrary registry execution;
- transaction is journaled with session/correlation ID, stage, path, before/after hash, rollback artifact hash, duration and exact failure reason;
- partial failure must trigger rollback of already-applied operations and report rollback success/failure explicitly;
- repair success never implies recovery certification; RR-6 owns certification;
- no disk format, partition/MBR/GPT/boot-sector/firmware mutation;
- no automatic process kill, live host isolation or cloud dependency;
- preserve RR-0 through RR-3 regression gates and B2 protected sources byte-identical.

RR-4 first acceptance uses harmless synthetic offline fixtures only. Real-machine repair remains blocked until reversible transaction semantics pass deterministic and Windows-live fixture gates.

## Future Rescue milestones
- RR-5 Safe Data Rescue: bounded data extraction from compromised systems without carrying active threats into clean environments.
- RR-6 Integrity Verification & Recovery Certification: multi-signal integrity validation; refuse certification when trust cannot be demonstrated.

Formatting/reimaging remains the last-resort recovery option and may never be suppressed when system integrity cannot be demonstrated.

## Safety invariants carried through Beta3
- B2 Protection Service/realtime/EDR sources are not modified by RR-0/RR-1/RR-2/RR-3/RR-4 work;
- no single heuristic HIGH;
- no heuristic-only destructive response;
- no automatic process kill or host isolation;
- signed IOC and Web Protection safeguards remain unchanged;
- no HTTPS MITM/root CA/TLS interception;
- no mandatory cloud runtime dependency;
- frozen service performance thresholds `25 / 10 / 250` are not weakened.

## Codex reasoning policy
- **Extra High**: Rescue architecture, trust boundaries, offline/boot parsing, repair transactions and integrity certification.
- **High**: ordinary implementation/test/integration after the relevant security boundary is frozen.
- milestone-by-milestone only; no future repair capability may be pulled forward merely to make a demo appear complete.
