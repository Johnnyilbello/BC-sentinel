# BC Sentinel v0.11.0-beta.3 — RR-5 Safe Data Rescue

## Purpose
RR-5 extracts explicitly selected user data from a validated offline Windows installation into a clean Rescue destination while keeping the source read-only and separating potentially active content from ordinary rescued data.

RR-5 does not claim that copied documents are malware-free. It reduces cross-contamination risk by using strict selection, SHA-256 verification, conservative file disposition and a dedicated containment tree.

## Trust boundary
Source:
- validated offline Windows root (`SYSTEM` hive + `ntoskrnl.exe` markers);
- read-only from RR-5's perspective;
- first checkpoint accepts selections only below `Users/<profile>`;
- no source binary/script/DLL execution;
- no registry/boot/source mutation.

Destination:
- must be outside the offline source tree;
- must be a normal non-reparse directory and empty before extraction;
- contains `rescued-data/`, `containment/`, manifest and audit output.

## Explicit selection
At least one `--include` is mandatory. Whole-disk blind extraction is not available in RR-5 initial scope.

Example selections:
```text
Users/Alice/Documents
Users/Alice/Pictures
Users/Alice/Desktop/report.docx
```

Selections outside `Users/<profile>` and path traversal are refused.

## Disposition
`rescued-data`:
- only extensions on the passive allowlist such as plain text, common images/audio/video and non-macro office formats;
- only when not matched by an explicitly approved local SHA-256 IOC.

`containment`:
- executables, DLLs, drivers, installers;
- scripts and shortcuts;
- macro-enabled Office files;
- archives/disk images;
- explicitly approved hash IOC matches;
- unknown extensions.

Containment means copied for evidence/data preservation only. RR-5 never executes or restores contained files automatically.

## Integrity
For each copied item RR-5 records:
- source-relative path;
- byte size;
- source SHA-256;
- disposition;
- destination-relative path;
- status/reason;
- IOC name when applicable.

During copy RR-5 re-checks source stat/hash and verifies the temporary destination SHA-256 before atomic placement. A source that changes while extraction is in progress is reported as an error and is not silently accepted.

## Resource bounds
Default limits:
- max files: 20,000;
- total considered bytes: 128 GiB;
- max single file: 4 GiB;
- max traversal depth: 32.

Hard limits prevent unbounded traversal/resource use.

## Audit
`rr5-audit.jsonl` records profile, session/correlation IDs, stage, status, reason, source, destination, elapsed time and per-item hash/size/disposition where applicable.

`rr5-rescue-manifest.json` records the complete extraction result and safety flags.

## Portable build
PyInstaller `onedir` artifact:
```text
dist\Rescue\BC-Sentinel-Rescue-Data-Portable\BC-Sentinel-Rescue-Data-Portable.exe
```

The build writes `safe-data-rescue-integrity.json` containing the executable SHA-256 and explicit no-installer/no-service/no-driver flags.

## Acceptance
RR-5 must preserve all RR-0 through RR-4B regression gates and B2 protected source hashes.

Deterministic and Windows-live fixtures must prove:
- normal passive data reaches only `rescued-data`;
- EXE/script/macro/unknown content reaches only `containment`;
- a passive-extension file matched by an approved SHA-256 IOC is forced into containment;
- every copied file has exact source/destination/manifest SHA-256 equality;
- source tree stays byte-identical;
- no service is installed;
- no repair, delete, registry/boot write, auto-restore or recovery certification is enabled.

## Deferred
RR-5 does not perform:
- automatic sanitization of Office/PDF/media content;
- archive unpacking;
- automatic restore onto a clean Windows host;
- live-host mutation;
- recovery certification.

RR-6 owns integrity verification and recovery certification.
