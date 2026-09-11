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

Accepted scope:
- validated offline Windows target only; live-host repair remains disabled;
- exact SHA-256 plan hash and explicit operator confirmation bound to that plan;
- replacement source must be outside the offline target and hash-verified before use;
- target pre-state hash checked immediately before mutation;
- verified rollback copy created outside the offline target before the first write;
- atomic replacement and post-state SHA-256 verification;
- transaction journal persisted with session/plan identity and exact operation state;
- manual rollback supported and verified;
- stale precondition fails closed and preserves the target;
- partial transaction failure automatically rolls back already-applied operations;
- boot, registry hive and identity-critical targets remain refused in RR-4A;
- no arbitrary shell/command execution;
- no automatic repair, no recovery certification and no cloud dependency;
- B2 protected sources remain byte-identical.

Authoritative FULL Windows evidence:
- RR-0 through RR-4A regression: **88 tests PASS**;
- deterministic RR-0/RR-1/RR-2/RR-3/RR-4A acceptance: **PASS**;
- wrong confirmation refused and target unchanged;
- repair plan SHA-256 `7f5e5bb23293b0a81fd569a10ac2730f7cf3b4fea1d6e15606f001c7a64b32c2`;
- rollback backup SHA-256 matched the pre-state hash;
- repair applied and verified;
- manual rollback passed and restored original content;
- stale precondition refused and stale target preserved;
- induced partial failure triggered automatic rollback and restored all already-applied operations;
- final transaction state `rolled_back`;
- automatic repair, live-host repair, registry write, boot write and recovery certification remained disabled;
- B2 protected sources remained unchanged.

Final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-4A REVERSIBLE TRANSACTION CORE - PASS
BC SENTINEL v0.11.0-beta.3 RR-4A BOOTSTRAP - PASS
```

## RR-4B — Portable Repair Engine — current
Goal: package the accepted RR-4A transaction semantics into a portable Rescue tool without weakening any safety boundary.

Required first acceptance scope:
- PyInstaller `onedir` portable build, no installer/service/driver installation;
- normal standard-user execution on harmless offline fixtures;
- separate `plan`, `execute` and `rollback` phases;
- portable plan file contains exact target fingerprint, operation list, evidence references, pre/post SHA-256 and plan hash;
- execute requires the exact operator confirmation token derived from the accepted plan hash;
- wrong/missing confirmation must produce zero mutation;
- replacement sources remain external to the offline target and provenance-verified;
- rollback store remains outside the offline target and is verified before write;
- stale target or changed replacement source fails closed;
- manual rollback requires the same exact plan-bound confirmation and refuses rollback if post-repair state has changed unexpectedly;
- no live-host repair, registry-hive mutation, boot/BCD/firmware mutation, arbitrary command execution or automatic repair;
- no recovery certification; RR-6 owns certification;
- preserve RR-0 through RR-4A regression gates and B2 protected sources byte-identical.

RR-4B acceptance uses harmless synthetic offline fixtures only. Real-machine repair remains blocked until the portable engine passes deterministic and built-binary Windows gates.

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
