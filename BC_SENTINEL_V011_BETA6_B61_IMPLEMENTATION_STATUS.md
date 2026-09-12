# BC Sentinel v0.11.0-beta.6 — B6-1 Implementation Checkpoint 1

Status: **IMPLEMENTED ON FEATURE BRANCH / LOCAL GATE DEFINED / WINDOWS ACCEPTANCE PENDING**

Branch: `feature/v011-beta6-b61-unified-home-innovation-roadmap`

Parent stable checkpoint remains unchanged:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

## Implemented in this checkpoint

- new unified Home target-discovery model;
- new `BC Sentinel - Home` PySide6 surface;
- explicit operator-triggered discovery, with no discovery command at startup;
- deterministic statuses: `RECOMMENDED`, `AVAILABLE`, `NEEDS_ATTENTION`, `AMBIGUOUS`, `UNSUPPORTED`;
- exactly one uniquely validated READY target may be marked `RECOMMENDED`;
- multiple distinct READY targets remain `AVAILABLE` and require explicit user choice;
- duplicate target identities/fingerprints are marked `AMBIGUOUS` and blocked;
- locked/encrypted, incomplete, inaccessible and unsupported targets fail closed;
- full discovery record retained under **Advanced details**;
- target selection stores identity but does not start scan, Rescue or remediation;
- target fingerprint/root revalidation helper for later privileged workflows;
- B6-1 deterministic pytest coverage;
- B6-1 synthetic acceptance tool;
- B6-1 PowerShell gate that runs accepted B6-0 first and verifies frozen/predecessor source hashes.

## Safety state

No B6-0/Beta5 destructive authority is added or exposed.

```text
automatic discovery            = false at startup
automatic target selection     = false
automatic rescue dispatch      = false
automatic repair               = false
automatic quarantine           = false
unlock attempt                 = false
write mount                    = false
format execution               = false
reimage execution              = false
registry/boot write authority  = false
target execution               = false
```

The discovery button is a deliberate user action and calls only the accepted read-only Beta5 discovery engine.

## Advanced details contract

The Home card gives the user a short status and recommendation. Technical evidence remains inspectable, including all fields currently supplied by the discovery engine and the complete raw discovery record. Future engine fields therefore remain available without requiring the simple Home card to expose them by default.

## Acceptance boundary

This checkpoint must **not** be called stable solely because source/tests/gates exist in Git.

Before B6-1 can be frozen as an accepted checkpoint, the Windows gate still requires real-device evidence for:

- real Windows target discovery;
- multi-disk / multi-volume behavior;
- locked BitLocker target refusal with no unlock attempt;
- no target write during discovery/selection;
- stale/changed fingerprint refusal;
- B6-0 predecessor gate still green;
- UI offscreen smoke and deterministic tests green;
- acceptance evidence committed.

Until those checks are executed successfully, B6-1 remains an active feature milestone and B6-0 remains the latest stable release.
