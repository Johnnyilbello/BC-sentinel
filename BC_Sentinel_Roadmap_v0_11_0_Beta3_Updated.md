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

Accepted scope:
- no installer, Protection Service or driver installation;
- normal non-elevated Windows execution supported and verified;
- no registry/boot/target-filesystem writes;
- no delete, kill, quarantine execution, repair execution or recovery certification;
- bounded read-only filesystem enumeration;
- SHA-256 evidence acquisition;
- symlink/reparse traversal not followed by default;
- bounded item/file-size limits;
- evidence output outside the target tree;
- per-file read/stat failures contained in evidence;
- no network/cloud runtime dependency;
- PyInstaller `onedir` portable build, avoiding onefile extraction into compromised TEMP;
- portable executable SHA-256 provenance manifest;
- real standard-user launch acceptance on harmless fixtures;
- target hashes remain identical before/after acquisition;
- runtime does not register a Windows service.

Authoritative FULL Windows evidence:
- isolated pytest temp root outside problematic `%TEMP%` cleanup path;
- RR-0 + RR-1 regression: **40 tests PASS**;
- deterministic RR-0 regression acceptance: **PASS**;
- deterministic RR-1 acceptance: **PASS**;
- RR-1 deterministic target summary: enumerated `2`, hashed `2`, skipped `0`, errors `0`;
- portable PyInstaller onedir build: **PASS**;
- portable binary SHA-256 `9deac6fed9dfc27b091f060ffe9887a161fdf31a034d4cb656849e8fe17f34f9`;
- built executable launched successfully as standard user;
- live harmless fixture: `2/2` SHA-256 evidence records;
- live target content unchanged before/after acquisition;
- no Rescue Windows service registered;
- B2 Protection Service/realtime/EDR sources remained protected and unchanged by the bootstrap.

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

## RR-2 — Rescue USB — current
Goal: turn the accepted RR-1 portable runtime into a trusted removable-media rescue workflow without introducing destructive disk preparation.

Required first acceptance scope:
- prepare a Rescue USB payload in a user-selected destination directory/removable volume;
- never format a disk, modify partition tables, write MBR/GPT/boot sectors, install a bootloader or alter firmware/BCD in RR-2 initial scope;
- refuse preparation when destination is the Windows system volume or when source/destination overlap unsafely;
- copy the accepted RR-1 portable payload plus RR-0/RR-1/RR-2 metadata only;
- generate a deterministic SHA-256 manifest for every prepared Rescue payload file;
- verify the complete prepared payload after copy and detect corruption/tampering;
- support read-only discovery of candidate offline Windows installations from mounted volumes/directories without modifying them;
- bound traversal, file count and resource use; do not follow symlink/reparse targets by default;
- produce structured audit records with stage, reason, source, destination, counts, duration and correlation/session identifiers;
- no network/cloud dependency;
- no malware repair, quarantine execution, registry write, boot write, target filesystem mutation or recovery certification;
- preserve RR-0 and RR-1 regression gates and keep B2 Protection Service/realtime/EDR byte-identical.

RR-2 acceptance must include a real Windows harmless-media simulation using an isolated directory or non-system removable destination before any future bootable-media work is considered.

## Future Rescue milestones
- RR-3 Offline Threat Scanner: deeper offline malware/persistence/boot/startup inspection using accepted intelligence primitives.
- RR-4 Repair Engine: reversible, provenance-backed repair transactions with operator confirmation and rollback.
- RR-5 Safe Data Rescue: bounded data extraction from compromised systems without carrying active threats into clean environments.
- RR-6 Integrity Verification & Recovery Certification: multi-signal integrity validation; refuse certification when trust cannot be demonstrated.

Formatting/reimaging remains the last-resort recovery option and may never be suppressed when system integrity cannot be demonstrated.

## Safety invariants carried through Beta3
- B2 Protection Service/realtime/EDR sources are not modified by RR-0/RR-1/RR-2 work;
- no single heuristic HIGH;
- no heuristic-only destructive response;
- no automatic file delete, process kill or host isolation;
- signed IOC and Web Protection safeguards remain unchanged;
- no HTTPS MITM/root CA/TLS interception;
- no mandatory cloud runtime dependency;
- frozen service performance thresholds `25 / 10 / 250` are not weakened.

## Codex reasoning policy
- **Extra High**: Rescue architecture, trust boundaries, offline/boot parsing, repair transactions and integrity certification.
- **High**: ordinary implementation/test/integration after the relevant security boundary is frozen.
- milestone-by-milestone only; no future repair capability may be pulled forward merely to make a demo appear complete.
