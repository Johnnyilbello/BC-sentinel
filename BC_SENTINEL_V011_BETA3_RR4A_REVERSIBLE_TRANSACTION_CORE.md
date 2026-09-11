# BC Sentinel v0.11.0-beta.3 — RR-4A Reversible Transaction Core

RR-4A is the first Rescue milestone allowed to mutate an offline target. It is intentionally narrower than the final Repair Engine.

## Allowed in RR-4A
- validated offline Windows roots only;
- replacement of an existing regular file only;
- trusted replacement source located outside the offline target;
- exact SHA-256 precondition for the target file;
- exact SHA-256 provenance for the replacement file;
- explicit evidence reference for every planned operation;
- plan hash binding target fingerprint + operations + provenance;
- explicit operator confirmation bound to the exact plan hash;
- verified rollback copy outside the target before mutation;
- atomic replacement followed by post-state SHA-256 verification;
- transaction journal and structured audit log;
- automatic rollback of already-applied operations after partial failure;
- explicit manual rollback after a successful transaction.

## Explicitly refused
- live Windows repair;
- automatic repair from RR-3 findings;
- heuristic-only repair triggers;
- arbitrary command/shell/script execution;
- file deletion as a repair primitive;
- registry hive writes;
- BCD, bootloader, MBR/GPT, boot-sector or firmware writes;
- replacement of RR-4A identity markers (`SYSTEM` hive / `ntoskrnl.exe`);
- source files located inside the compromised/offline target;
- path traversal, symlink/reparse traversal and rollback storage inside the target;
- recovery certification.

RR-4A success means only that the transaction mechanism is reversible and controlled. It does not certify that a machine is clean or recovered.

## Acceptance gates
1. RR-0/RR-1/RR-2/RR-3 regressions remain green.
2. RR-4A targeted tests pass.
3. Wrong operator confirmation performs zero target mutation.
4. Exact repair plan applies a harmless replacement and verifies before/after hashes.
5. Rollback artifact hash matches the original target hash.
6. Manual rollback restores the original target bytes.
7. A stale target precondition is refused without overwriting the newer target state.
8. A changed replacement source is refused.
9. A failure on a later operation rolls back earlier operations.
10. B2 Protection Service/realtime/EDR protected sources remain byte-identical.

Portable repair execution is deferred to RR-4B after RR-4A passes on the authoritative FULL Windows tree.
