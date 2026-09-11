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

## RR-1 — Portable — current
Goal: run the first operational Rescue acquisition runtime from a normal folder or trusted external media without installing BC Sentinel.

Required scope:
- no installer, Protection Service or driver installation;
- normal non-elevated Windows execution must be supported;
- no registry/boot/target-filesystem writes;
- no delete, kill, quarantine execution, repair execution or recovery certification;
- bounded read-only filesystem enumeration;
- SHA-256 evidence acquisition;
- symlink/reparse traversal not followed by default;
- bounded item/file-size limits;
- evidence output must be outside the target tree;
- per-file read/stat failures contained and represented in evidence;
- no network/cloud runtime dependency;
- portable build uses PyInstaller `onedir` to avoid onefile extraction into compromised TEMP;
- portable executable SHA-256 provenance manifest;
- real standard-user launch acceptance on harmless fixtures;
- target hashes must remain identical before/after acquisition;
- runtime must not register a Windows service.

RR-1 acceptance requires the authoritative FULL Windows run to reach:

```text
BC SENTINEL v0.11.0-beta.3 RR-1 PORTABLE - PASS
```

## Future Rescue milestones
- RR-2 Rescue USB: trusted-media preparation, integrity verification, startup workflow and offline-target discovery.
- RR-3 Offline Threat Scanner: deeper offline malware/persistence/boot/startup inspection using accepted intelligence primitives.
- RR-4 Repair Engine: reversible, provenance-backed repair transactions with operator confirmation and rollback.
- RR-5 Safe Data Rescue: bounded data extraction from compromised systems without carrying active threats into clean environments.
- RR-6 Integrity Verification & Recovery Certification: multi-signal integrity validation; refuse certification when trust cannot be demonstrated.

Formatting/reimaging remains the last-resort recovery option and may never be suppressed when system integrity cannot be demonstrated.

## Safety invariants carried through Beta3
- B2 Protection Service/realtime/EDR sources are not modified by RR-0/RR-1 work;
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