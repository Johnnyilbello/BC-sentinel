# BC Sentinel v0.11.0-beta.6 — B6-1 Target Discovery & Selection UX

Status: **PLANNED / ACTIVE FEATURE BRANCH**

Branch: `feature/v011-beta6-b61-unified-home-innovation-roadmap`

Parent stable checkpoint:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```

## Objective

B6-1 is the first milestone of the unified BC Sentinel Home experience.

The goal is to let a normal user identify and select the correct Windows target safely, while preserving complete technical evidence under **Advanced details**.

B6-1 must not introduce a separate Technician mode.

## UX contract

Default view answers only the questions the user needs:

```text
Which Windows installation did BC Sentinel find?
Which one is recommended?
Is it safe to analyze?
Is anything preventing analysis?
What should I do next?
```

Advanced details exposes the underlying technical evidence.

## Required target card

Each discovered target should be represented by a card containing, where available:

- friendly label, e.g. `Windows 11`;
- drive/volume label;
- approximate used/total size;
- status: `Recommended`, `Available`, `Needs attention`, `Unsupported` or `Ambiguous`;
- short plain-language explanation;
- one safe primary action: `Select` / `Analyze` when permitted;
- `Advanced details` disclosure.

The UI must never imply that an ambiguous target is safe merely because it was discovered.

## Advanced details

Expose, where available:

```text
physical disk identifier
partition identifier
partition table / type
volume identifier
filesystem
mount state
read-only state
Windows root candidate
Windows version/build evidence
encryption / BitLocker state
unlock state
discovery confidence
discovery evidence
fingerprint / target identity
supported / unsupported reason
ambiguity reason
```

No technical evidence should be removed from the model to simplify the visible card.

## Recommendation model

Target recommendation must be deterministic and explainable.

A recommendation may use evidence such as:

- valid Windows directory structure;
- registry hive presence;
- boot/system evidence;
- filesystem support;
- target identity/fingerprint stability;
- encryption accessibility state;
- absence of ambiguity with another equally plausible installation.

Recommendation output:

```text
RECOMMENDED
AVAILABLE
NEEDS_ATTENTION
AMBIGUOUS
UNSUPPORTED
```

`RECOMMENDED` must not bypass any existing safety refusal.

## Safety invariants

B6-1 must preserve the B6-0/Beta5 trust boundary.

```text
automatic rescue dispatch      = false
automatic repair               = false
automatic quarantine           = false
repair-execute exposed         = false
unlock exposed                 = false
mount-write exposed            = false
format execution               = false
reimage execution              = false
registry/boot write authority  = false
target execution               = false
```

Additional B6-1 rules:

- discovery is read-only;
- target code is never executed;
- encrypted/locked volumes fail closed;
- ambiguity never becomes implicit consent;
- no automatic unlock attempt;
- no write mount;
- no hidden target mutation;
- selection does not itself start a Rescue command;
- a target fingerprint must be revalidated before later privileged workflows.

## States

Suggested UX states:

```text
DISCOVERING
NO_TARGETS
TARGETS_FOUND
TARGET_SELECTED
TARGET_NEEDS_ATTENTION
TARGET_AMBIGUOUS
TARGET_UNSUPPORTED
DISCOVERY_ERROR
```

These UI states must not replace the engine's accepted safety/refusal semantics.

## Empty / error cases

The UX must explicitly handle:

- no disks found;
- disk present but no Windows installation found;
- multiple Windows installations;
- damaged filesystem;
- unsupported filesystem;
- locked BitLocker/encrypted target;
- removable media only;
- ambiguous boot/system evidence;
- stale/disappeared target;
- discovery exception;
- target identity changed between discovery and selection.

## Accessibility and usability

- keyboard navigation for every target card and disclosure;
- screen-reader-friendly labels;
- no critical state expressed by color alone;
- clear focus state;
- long disk/volume labels must not break layout;
- details must remain readable on the minimum supported window size;
- destructive-looking language must not be used for read-only actions.

## Detection & Attack Coverage integration

B6-1 is primarily UX, but it must already comply with the permanent coverage program:

- discovery evidence must be reproducible;
- damaged/hostile targets must have deterministic fixtures;
- false target recommendations count as coverage/safety defects;
- unsupported targets must fail visibly rather than disappear silently;
- target-discovery regressions must be tracked across future releases.

## Innovation Program integration

B6-1 prepares future innovation work by defining a stable target identity that can later connect:

```text
live incident
-> Security Graph
-> Rescue target
-> Rescue Continuity
-> recovery verification
```

No Attack Prediction or autonomous remediation is introduced in B6-1.

## Acceptance tests

Minimum deterministic tests:

1. one healthy supported Windows target -> exactly one `RECOMMENDED` target;
2. two valid Windows targets -> explicit multi-target selection, no silent auto-selection;
3. locked encrypted target -> `NEEDS_ATTENTION` or `UNSUPPORTED`, no unlock attempt;
4. damaged target -> visible reason, no crash, no write;
5. non-Windows volume -> not recommended as Windows target;
6. stale/disappeared target -> selection refused after identity revalidation;
7. ambiguous evidence -> `AMBIGUOUS`, no automatic progression;
8. advanced details retain full discovery evidence;
9. startup performs no engine command;
10. forbidden command inventory remains absent;
11. offscreen UI smoke test passes;
12. existing B6-0 safety contract remains green.

## Windows acceptance gate

B6-1 may only become stable after:

- deterministic unit tests pass;
- B6-0 regression tests pass;
- UI smoke test passes;
- real Windows discovery is validated on supported configurations;
- multi-disk/multi-volume scenario is tested;
- encrypted/locked target refusal is verified;
- no target write is observed during discovery/selection;
- no forbidden command becomes reachable;
- target fingerprint revalidation is proven;
- acceptance evidence is committed.

## Codex execution policy

**Recommended reasoning:**

- `High` for ordinary B6-1 UI/model implementation and tests;
- `Extra High` for any change to target identity, disk/volume parsing, encryption handling, safety boundaries or privileged behavior.

Work one checkpoint at a time. Do not weaken an existing safety test to make B6-1 pass.

## Definition of done

A user can open BC Sentinel, see discovered Windows targets in understandable language, identify the recommended target, inspect complete technical details if desired, make an explicit selection, and proceed to the next read-only workflow without BC Sentinel performing any hidden mutation or destructive action.
