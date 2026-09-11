# BC Sentinel v0.11.0-beta.5 — B5-7 Portable Technician Release

## Purpose
B5-7 packages the accepted Beta4 Rescue Console plus the accepted Beta5 hardening modules into a final portable technician launcher. It is packaging/integration only: it adds no new repair, unlock, quarantine, format, reimage, registry-write, boot-write or target-execution authority.

## Frozen predecessor
B5-7 starts exactly from:

```text
checkpoint/v011-beta5-b56-pass
7c86e087f0fe7769bf752889de82660a9c4c98f4
```

All Beta3, Beta4 and B5-0 through B5-6 checkpoints remain immutable.

## Portable command surface
The launcher exposes only:

```text
plan
scan
repair-handoff
data-rescue
certify
discover
assess
stress
resume
decide
report
status
```

Explicitly not exposed:

```text
repair-execute
unlock
format
reimage
quarantine-execute
```

`repair-handoff` remains handoff only. Repair mutation remains delegated to the frozen RR4B engine and requires its existing exact confirmation contract outside this launcher.

## Component binding
- plan: B4-0
- scan: B4-1
- repair-handoff: B4-2
- data-rescue: B4-3
- certify: B4-4 / RR-6 outcome preservation
- portable base: B4-5
- discover: B5-0
- assess: B5-1
- stress: B5-2
- resume: B5-3
- decide: B5-4
- report: B5-5
- controlled real-PC acceptance predecessor: B5-6

## Packaging contract
- PyInstaller `onedir`;
- standard-user execution for the acceptance gate;
- no installer;
- no Windows service registration;
- no driver install;
- no network/cloud dependency;
- integrity manifest with EXE SHA-256;
- bounded short build work/temp directories;
- up to three isolated build attempts with diagnostic logs;
- B2 service/realtime/EDR sources must remain byte-identical.

## B5-7 acceptance
B5-7 does not pass unless all conditions below are true:

1. accepted B5-6 complete gate passes first;
2. 20 B5-7 tests pass;
3. deterministic launcher acceptance passes;
4. target remains byte-identical through `discover`, `assess`, `stress` and `resume init`;
5. PyInstaller onedir build succeeds;
6. integrity manifest SHA-256 matches the built EXE;
7. built `status` reports profile `v0.11.0-beta.5-b57` and the exact command surface;
8. built `repair-execute`, `unlock`, `format` and `reimage` are refused with exit code 2;
9. built legacy commands load and `plan`/`scan` execute on a controlled offline target;
10. built `discover`, `assess`, `stress` and `resume init` execute successfully;
11. built `decide` and `report` parsers load;
12. controlled target remains unchanged after the built-artifact workflow;
13. no B5-7 Windows service is registered;
14. protected B2 service/realtime/EDR sources remain unchanged.

With 301 tests already covered through B5-6 plus 20 B5-7 tests, successful acceptance gives **321 cumulative tests covered**.

## Safety / refusal semantics
- RR-6 outcomes remain exactly `RECOVERED`, `NOT_RECOVERED`, `INDETERMINATE_REFUSED`;
- no advisory layer can override RR-6;
- incomplete or untrusted evidence is never upgraded to success;
- format/reimage remains a valid last resort and is never suppressed;
- the optional real problematic-PC scenario remains distinct from the controlled B5-6 acceptance and is never fabricated.

## Logging policy
Every critical failure must expose stage, reason, relevant path, exit code, counters/hashes where useful, and build-log location when the failure occurs during packaging.

## Freeze condition
Only after the authoritative Windows B5-7 gate is fully green may the exact tested head be frozen as `checkpoint/v011-beta5-b57-pass` and Beta5 be closed.
