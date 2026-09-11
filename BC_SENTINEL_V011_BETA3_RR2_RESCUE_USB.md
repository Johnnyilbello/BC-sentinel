# BC Sentinel v0.11.0-beta.3 — RR-2 Rescue USB

## Purpose
RR-2 prepares and verifies the accepted RR-1 portable Rescue payload on trusted removable media while preserving the RR-0 safety boundary.

## Current safety boundary
RR-2 does **not** format disks, repartition media, write MBR/GPT/boot sectors, install a bootloader, modify BCD/firmware, write the offline registry, repair malware, execute quarantine, delete target files, or certify recovery.

The first RR-2 gate proves the removable-media packaging and integrity workflow before any future bootable-media capability is considered.

## Preparation contract
- source is the accepted RR-1 `onedir` portable payload;
- destination must already exist and be empty;
- existing destination content is never deleted;
- direct filesystem roots are refused;
- source/destination overlap is refused;
- symlink/reparse source and destination roots are refused;
- real preparation requires Windows and a non-system removable drive;
- fixed/system/network/unknown destinations are refused in real mode;
- a dedicated `--simulation` mode exists only for harmless acceptance in an isolated directory;
- source enumeration is bounded by file-count and total-byte limits;
- symlink/reparse descendants are not followed by default;
- every copied file is SHA-256 checked against its source;
- a complete deterministic manifest is written and immediately reverified.

## Prepared media layout
```text
<selected empty destination>/
  payload/
    <RR-1 portable onedir files>
  rescue-usb-manifest.json
  rescue-usb-audit.jsonl
```

`rescue-usb-manifest.json` records profile, session/correlation IDs, source/destination, limits, file count/bytes, per-file relative path/size/SHA-256, and explicit safety flags.

`rescue-usb-audit.jsonl` records exact stage/status/reason, source, destination, elapsed time and correlation identifiers. A failure is expected to identify its exact stage and reason instead of collapsing into a generic message.

## Verification
`verify` re-enumerates the payload without following reparse targets and validates:
- expected file set;
- unexpected files;
- missing files;
- file sizes;
- SHA-256 hashes;
- profile consistency.

Corruption or tampering makes verification fail closed.

## Offline Windows discovery
RR-2 can identify candidate offline Windows roots using only read-only presence checks for:
- `Windows/System32/config/SYSTEM`
- `Windows/System32/ntoskrnl.exe`

Discovery does not mount hives, write the registry, alter BCD or modify the target. Deeper offline inspection belongs to RR-3.

## Acceptance
The authoritative FULL Windows gate must prove:
- RR-0 + RR-1 + RR-2 tests pass using an isolated pytest temp root;
- deterministic RR-0/RR-1/RR-2 acceptance passes;
- the RR-1 portable payload rebuild succeeds;
- harmless USB-directory simulation preparation succeeds;
- manifest verification succeeds;
- structured audit contains `prepare_start`, `prepare_complete`, `reason`, and `correlation_id`;
- harmless offline Windows candidate is found read-only;
- source portable executable remains byte-identical;
- fake offline target remains byte-identical;
- B2 Protection Service/realtime/EDR sources remain byte-identical;
- destructive disk/boot/repair flags remain false.

Final expected gate:
```text
BC SENTINEL v0.11.0-beta.3 RR-2 RESCUE USB - PASS
```

## Next milestone
RR-3 adds offline threat scanning and persistence/startup inspection. RR-2 does not pull RR-3 or RR-4 repair capabilities forward.
