# BC Sentinel v0.11.0-beta.3 — RR-3 Offline Threat Scanner

## Goal
RR-3 adds a portable, offline, **read-only** threat-analysis layer for Windows installations discovered from trusted Rescue media.

RR-3 detects and records evidence. It does not repair, delete, quarantine, execute target code, change the registry/boot chain or certify a machine as recovered.

## Accepted predecessor
RR-2 Rescue USB is frozen at:

```text
checkpoint/v011-beta3-rr2-pass
```

RR-3 is developed separately so the accepted RR-0/RR-1/RR-2 safety boundary is preserved.

## Scanner scope
The first RR-3 scanner:

- validates the offline Windows root using the offline `SYSTEM` hive and `ntoskrnl.exe` markers;
- inspects executable/script artifacts in bounded high-risk Windows, driver, startup and user-temp paths;
- hashes inspected files with SHA-256;
- supports an explicitly approved local SHA-256 IOC catalog;
- supports optional local YARA rules when `yara-python` is available;
- remains functional without YARA, network or cloud access;
- records offline registry hive presence/size/hash metadata without loading hives into the live registry;
- surfaces startup scripts, executable/script artifacts in user TEMP, suspicious LOLBin-name placement and double-extension lures for operator review;
- writes results and structured JSONL audit logs only outside the offline target.

## Trust and safety boundaries
RR-3 must never:

- execute a file from the offline target;
- load a DLL/driver from the offline target;
- shell into the offline target;
- write the offline registry;
- write BCD/boot sectors/firmware;
- modify the target filesystem;
- delete files;
- kill processes;
- execute quarantine;
- execute a repair plan;
- automatically act on a heuristic finding;
- certify recovery.

An exact approved SHA-256 IOC or a YARA match is detection evidence only. Destructive/remediation behavior remains deferred to RR-4 and must use a separate reversible transaction design.

## Resource bounds
Defaults:

- max files: 10,000;
- max bytes per scanned file: 64 MiB;
- hard max files: 50,000;
- hard max bytes per file: 256 MiB;
- YARA per-file timeout: 2 seconds;
- symlink/reparse traversal refused by default.

## Observability
Every scan produces `rr3-audit.jsonl` with:

- profile;
- session ID;
- correlation ID;
- stage;
- status;
- reason;
- offline root;
- elapsed milliseconds;
- summary counters on completion/failure.

Primary evidence output is `rr3-offline-scan.json`.

## Windows acceptance
The gate must run from normal non-elevated PowerShell and prove:

1. RR-0/RR-1/RR-2/RR-3 tests are green with an isolated pytest temp root.
2. RR-0/RR-1/RR-2 deterministic acceptances remain green.
3. RR-3 deterministic acceptance is green.
4. A dedicated PyInstaller `onedir` scanner builds successfully.
5. Its SHA-256 matches `offline-scanner-integrity.json`.
6. A harmless synthetic offline Windows tree is scanned by the built EXE.
7. One approved harmless SHA-256 IOC is detected deterministically.
8. Startup and double-extension review evidence is surfaced.
9. Target hashes are identical before/after scan.
10. No Rescue Offline Scanner Windows service is registered.
11. B2 Protection Service/realtime/EDR protected sources remain byte-identical.

Expected final gates:

```text
BC SENTINEL v0.11.0-beta.3 RR-3 OFFLINE THREAT SCANNER - PASS
BC SENTINEL v0.11.0-beta.3 RR-3 BOOTSTRAP - PASS
```

## Not claimed by RR-3
RR-3 does not yet claim full offline registry key/value parsing, bootkit repair, filesystem repair, safe quarantine transactions, data rescue or recovery certification. Those capabilities remain gated by later Rescue milestones.
