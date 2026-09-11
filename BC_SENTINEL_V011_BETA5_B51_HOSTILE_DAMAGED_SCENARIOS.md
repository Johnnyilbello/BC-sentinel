# BC Sentinel v0.11.0-beta.5 B5-1 — Hostile / Damaged System Scenarios

## Purpose
Harden Rescue assessment against damaged, slow, partially unreadable or persistence-contaminated offline Windows targets without adding automatic mutation authority.

## Frozen predecessor
```text
checkpoint/v011-beta5-b50-pass
385ba83a483f6a894dd7048cc2d3cec9c11e3a8e
```

B5-0 and all Beta3/Beta4 checkpoints remain immutable.

## Assessment states
- `HEALTHY`: bounded read-only probes completed without material findings.
- `REVIEW_REQUIRED`: suspicious persistence/startup material requires operator review.
- `DAMAGED`: critical Windows contract/files are missing or invalid.
- `ACCESS_RESTRICTED`: one or more required probes could not be read because of access restrictions.
- `IO_DEGRADED`: I/O errors, slow reads or time-budget degradation observed.
- `REFUSED`: assessment itself could not be safely performed.

No state automatically triggers repair, quarantine, deletion, execution, restore or certification.

## Read-only probes
B5-1 probes only bounded evidence:
- SYSTEM and SOFTWARE hives;
- ntoskrnl.exe;
- ProgramData startup directory;
- scheduled-task files;
- per-user Startup directories.

Files are sampled and hashed without loading or executing target code.

## Bounds
Defaults:
- max files: 512;
- max sampled bytes: 16 MiB;
- max assessment wall time: 8 seconds;
- max bytes sampled per file: 64 KiB;
- slow-read threshold: 250 ms.

Hard caps prevent unbounded probing.

## Safety invariants
- target read-only;
- no target execution or DLL loading;
- no registry writes;
- no boot/BCD writes;
- no delete;
- no repair execution;
- no quarantine execution;
- no automatic action;
- no network/cloud requirement;
- output must remain outside the target;
- symlink/reparse target roots are refused.

## Acceptance
Windows acceptance must prove:
- complete Beta3 + Beta4 + B5-0 regression remains green;
- 14 B5-1 tests pass;
- expected cumulative count: 226 tests;
- clean fixture -> `HEALTHY`;
- missing critical file -> `DAMAGED`;
- persistence fixture -> `REVIEW_REQUIRED`;
- deterministic permission injection -> `ACCESS_RESTRICTED`;
- deterministic I/O failure injection -> `IO_DEGRADED`;
- target byte-identical before/after;
- no service registration;
- protected B2 sources unchanged.

Only after authoritative Windows acceptance may `checkpoint/v011-beta5-b51-pass` be created.
