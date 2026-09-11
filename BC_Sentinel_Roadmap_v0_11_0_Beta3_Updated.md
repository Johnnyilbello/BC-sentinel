# BC Sentinel — Roadmap v0.11.0-beta.3 Rescue & Recovery

## Frozen predecessor
`v0.11.0-beta.2` is accepted and frozen at:

```text
checkpoint/v011-beta2-b2-pass-v6
b943f1ee550ad5c2bee3d8753962d5971c212381
```

Final B2 Windows gate: `BC SENTINEL v0.11.0-beta.2 B2 NONEXEC OBSERVATION V6 - PASS`.

## RR-0 — Architecture & Safety — accepted
Authoritative FULL Windows evidence:
- **22 tests PASS**;
- deterministic acceptance PASS;
- read-only default; destructive actions/file delete/process kill/host isolation/registry/boot/filesystem writes disabled;
- recovery certification disabled;
- SHA-256 evidence contract and bounded workers/inflight enabled.

Frozen checkpoint:
```text
checkpoint/v011-beta3-rr0-pass
efc78e88e7004ea9c4289c1aab233c92f34f7748
```

## RR-1 — Portable — accepted
Authoritative FULL Windows evidence:
- RR-0 + RR-1 regression: **40 tests PASS**;
- portable PyInstaller onedir build PASS;
- portable binary SHA-256 `9deac6fed9dfc27b091f060ffe9887a161fdf31a034d4cb656849e8fe17f34f9`;
- standard-user launch PASS, 2/2 evidence records, target unchanged, no service.

Frozen checkpoint:
```text
checkpoint/v011-beta3-rr1-pass
fbf5be7a9c00fb01d36834f431253b7eae7eb1f3
```

## RR-2 — Rescue USB — accepted
Authoritative FULL Windows evidence:
- RR-0..RR-2 regression: **53 tests PASS**;
- deterministic tamper detection PASS;
- offline Windows discovery read-only;
- live Rescue-media simulation: **56 files / 19,470,134 bytes**, verification **56/56**, source unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta3-rr2-pass
93c5082a3f9c7691df3e7905c763a129e8586bed
```

Boundary: RR-2 does not claim bootable-media creation and performs no format/partition/boot-chain write.

## RR-3 — Offline Threat Scanner — accepted
Authoritative FULL Windows evidence:
- RR-0..RR-3 regression: **75 tests PASS**;
- deterministic IOC PASS; local YARA included and live YARA hit PASS;
- scanner binary SHA-256 `02903b8340472b1ab51643d573cc0b522fb4a741592ec3b7a622b08c8618f805`;
- live target byte-identical; no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta3-rr3-pass
58f2767bf8d9460999d8647b07cfc00856355180
```

## RR-4A — Reversible Transaction Core — accepted
Authoritative FULL Windows evidence:
- RR-0..RR-4A regression: **88 tests PASS**;
- wrong confirmation zero mutation;
- verified backup before write;
- repair and manual rollback PASS;
- stale precondition refused;
- induced partial failure automatically rolled back all applied operations;
- no live repair/registry/boot write/certification.

Frozen checkpoint:
```text
checkpoint/v011-beta3-rr4a-pass
55d7dbbfedce76ea02f42ec0e661c63b8bef9f14
```

## RR-4B — Portable Repair Engine — accepted
Authoritative FULL Windows evidence:
- RR-0..RR-4B regression: **97 tests PASS**;
- separate plan/execute/rollback and exact plan-bound confirmation;
- portable repair binary SHA-256 `b748d6eae43cfd1152b269de30c152ffda89fdedd20532e1041867ceaaa634a5`;
- live plan SHA-256 `1e2bf6c3ce444c7a441b0d99f14f7fb47c560569c907a9a3d8a492cc90dfc0f3`;
- wrong-confirmation zero mutation, repair, verified rollback and changed-post-state rollback refusal PASS;
- no service; B2 sources unchanged.

Frozen checkpoint:
```text
checkpoint/v011-beta3-rr4b-pass
98f1900edba12606f2c0610a49774b14fb70020c
```

## RR-5 — Safe Data Rescue — accepted
RR-5 extracts explicitly selected user data from a validated offline Windows source while preventing active or ambiguous content from silently entering the clean-data tree.

Accepted scope:
- source read-only and destination outside source;
- explicit `Users/<profile>` selections only; no whole-disk blind copy;
- bounded files/bytes/file size/depth;
- no symlink/reparse traversal;
- SHA-256 source/destination verification;
- passive approved data placed in `rescued-data`;
- executable/script/shortcut/macro/archive/unknown or approved-IOC content placed in separate `containment`;
- no source execution/delete/repair/registry/boot mutation;
- no automatic restore and no recovery certification;
- structured manifest/audit with session/correlation IDs;
- B2 protected sources byte-identical.

Authoritative FULL Windows evidence:
- RR-0 through RR-5 regression: **116 tests PASS**;
- deterministic RR-0/RR-1/RR-2/RR-3/RR-4A/RR-4B/RR-5 acceptance: **PASS**;
- deterministic RR-5 fixture: `6` records copied, `5` contained, `0` skipped, `0` errors;
- only passive `notes.txt` entered the clean-data tree;
- unknown extension, macro document, executable, PowerShell script and an approved IOC disguised as `photo.jpg` were contained;
- all copied SHA-256 values verified and source remained unchanged;
- PyInstaller onedir Safe Data Rescue build: **PASS**;
- portable Safe Data Rescue binary SHA-256 `500dea1d22f1c865e27f74358d2263b396f7d09b4b4a41d7c986c57441cc728e`;
- live built-EXE summary: records `6`, copied `6`, contained `5`, skipped `0`, errors `0`;
- live `6/6` SHA-256 verification PASS;
- no Windows service registered;
- B2 Protection Service/realtime/EDR sources remained unchanged.

Final gates:
```text
BC SENTINEL v0.11.0-beta.3 RR-5 SAFE DATA RESCUE - PASS
BC SENTINEL v0.11.0-beta.3 RR-5 BOOTSTRAP - PASS
```

## RR-6 — Integrity Verification & Recovery Certification — current
Goal: decide whether an offline/recovered Windows installation has enough independently verified evidence to be declared recovered, and refuse certification whenever integrity cannot be demonstrated.

Required first acceptance scope:
- certification is a separate read-only phase after scan/repair/data-rescue evidence; it never mutates the target;
- validate an offline Windows root and bind the assessment to a deterministic target fingerprint;
- require multiple independent trust signals rather than relying on one scanner result;
- minimum evidence families: offline threat-scan result, critical-system-file integrity baseline, registry-hive presence/integrity metadata, repair-transaction state when repairs occurred, and Rescue lineage/provenance;
- certification must fail closed on missing/stale/tampered evidence, target fingerprint mismatch, unresolved deterministic IOC/YARA findings, scan errors/truncation, incomplete critical-file baseline, repair transaction not cleanly applied/rolled back, or provenance mismatch;
- heuristic-only observations may contribute context but may not independently deny or grant certification;
- no single weak signal may grant `RECOVERED`;
- explicitly distinguish `RECOVERED`, `NOT_RECOVERED`, and `INDETERMINATE/REFUSED` outcomes;
- `RECOVERED` requires all mandatory gates, zero unresolved high-confidence findings, zero evidence-integrity failures and complete provenance;
- `NOT_RECOVERED` is used when positive evidence proves an unresolved integrity/security problem;
- `INDETERMINATE/REFUSED` is used when required proof is missing or cannot be trusted;
- produce a deterministic certification report with target fingerprint, evidence hashes, checks, reasons, timestamp, session/correlation IDs and report SHA-256;
- report must explicitly state that certification is evidence-based and does not suppress reimage/format when trust cannot be demonstrated;
- no target execution, registry/boot write, delete, quarantine, repair or automatic destructive action in RR-6;
- preserve RR-0 through RR-5 regression gates and B2 protected sources byte-identical.

RR-6 acceptance uses harmless synthetic Windows fixtures and synthetic trustworthy/tampered/unresolved-threat evidence. It must prove both successful certification and deliberate refusal paths before Beta3 can close.

## Beta3 closure condition
Beta3 Rescue may close only after RR-6 passes deterministic + Windows built-binary gates and a frozen `checkpoint/v011-beta3-rr6-pass` is created. Formatting/reimaging remains the last-resort option whenever integrity cannot be demonstrated.

## Safety invariants carried through Beta3
- B2 Protection Service/realtime/EDR sources are not modified by RR-0..RR-6 work;
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
