# BC Sentinel v0.11.0-beta.6 B6-3 — One-Click Smart Scan

Status: SPECIFICATION OPEN / IMPLEMENTATION PENDING
Parent branch head: `46f56a6a0e3f17d1333b3b5a14539e6981cafb5a`
Parent milestone: B6-2 Home / Security Overview

## Context

B6-2 is CI-green on Windows and its visual/runtime-truth regression gate passes. Manual product-owner visual acceptance is still pending, so B6-2 is not promoted to the stable checkpoint. Product development continues into B6-3 while additional UI polish is intentionally deferred.

The repository remains a synchronization/delta tree for parts of the historical native protection runtime. Therefore B6-3 must not invent a live scanner API that is not present in the current source tree. The first B6-3 implementation introduces a truthful Smart Scan orchestration contract and only enables real execution when an accepted scan provider is explicitly supplied.

## Objective

Make one primary scan action understandable and safe:

`User action -> explicit plan -> bounded scan provider -> progress -> findings -> recommendation -> Advanced details`

Smart Scan chooses safe checks through an accepted provider instead of exposing low-level engine choices to the normal user.

## Product rules

- One Home experience; no separate Technician mode.
- Simple result first; complete technical evidence remains available through Advanced details.
- Smart Scan never starts at application startup.
- Clicking refresh never starts a scan.
- Navigation never starts or resumes a scan.
- Only explicit user action may start Smart Scan.
- Full Scan remains unavailable until it has its own accepted bounded contract.
- A completed scan with zero findings does not by itself mean real-time protection is active.
- Missing provider coverage is `INCOMPLETE`, never `CLEAN`.
- Provider failure is `FAILED`, never `CLEAN`.
- Cancellation is explicit and non-destructive.
- No automatic quarantine, delete, repair, process termination, registry write, boot write, unlock, write mount, format or reimage authority is introduced.

## B6-3 session states

Machine states:

- `IDLE`
- `PLANNED`
- `RUNNING`
- `COMPLETED_CLEAN`
- `COMPLETED_FINDINGS`
- `INCOMPLETE`
- `FAILED`
- `CANCELLED`

Terminal states are immutable for the completed session. A new scan creates a new session id.

## Smart Scan plan

The Home coordinator requests a plan from a provider using a small typed contract. Each check must declare:

- `check_id`
- friendly label
- purpose
- whether it is available
- provenance
- bounded work estimate when known

The coordinator must retain provider-declared unavailable checks in the final evidence package. It may not silently omit them.

## Provider boundary

B6-3 defines an injectable provider protocol rather than coupling the Home directly to historical implementation files.

Required provider behavior:

1. `capabilities()` returns truthful availability and provenance.
2. `plan()` returns the exact checks that would run and their availability.
3. `run(plan, progress_callback, cancel_check)` returns a result package.
4. The provider may report findings but may not perform remediation through this contract.
5. Results must include coverage status and raw evidence.

The repository default provider is intentionally unavailable until an accepted live-runtime bridge exists in the synchronized source tree. This is fail-closed behavior, not a missing-data workaround.

## Result model

A Smart Scan result contains at minimum:

- session id and correlation id
- start/end timestamps and elapsed time
- terminal state
- completed/total checks
- findings count
- highest severity
- coverage status (`COMPLETE` or `INCOMPLETE`)
- plain-language summary
- recommended next action
- provider name/profile/provenance
- per-check results
- raw evidence
- `automatic_quarantine=false`
- `automatic_repair=false`
- `automatic_destructive_action=false`

## Findings

A finding is evidence, not permission to remediate. Minimum fields:

- finding id
- title
- severity
- category
- reason
- source check id
- path/process/indicator only when supplied by the provider
- technical evidence payload
- confidence where available

No finding may be fabricated for UI demonstration in production runtime.

## Recommendation rules

- `COMPLETED_CLEAN` + complete coverage -> `No immediate action required from this scan. Keep protection enabled.`
- `COMPLETED_FINDINGS` -> `Review findings before taking action.`
- `INCOMPLETE` -> `Some checks could not run. Review coverage and retry or use System & Recovery if appropriate.`
- `FAILED` -> `Smart Scan could not complete. Review the error and retry.`
- `CANCELLED` -> `Scan cancelled. No remediation was performed.`

## Home integration

When an accepted provider is available:

- Dashboard `Scansione rapida` becomes enabled.
- Sidebar Quick Scan becomes enabled.
- Scansione page `Scansione rapida` becomes enabled.
- All three launch the same coordinator and therefore the same safety contract.
- While running, a second start request is refused.
- The Scansione page displays real session state/progress/result only.
- Full Scan remains disabled.

If no accepted provider is available, the buttons must remain disabled or explain the unavailable provider. The Home must not pretend a scan can execute.

## Concurrency

Real scan work must not run on the Qt GUI thread. UI integration must use a worker/thread boundary. UI callbacks may update presentation state only.

## Acceptance requirements

Deterministic tests must prove:

1. passive startup does not call `plan()` or `run()`;
2. navigation and refresh do not start Smart Scan;
3. no-provider state is truthful and non-executable;
4. explicit start creates one session only;
5. duplicate start while RUNNING is refused;
6. progress is monotonic and bounded 0..100;
7. complete zero-finding provider yields `COMPLETED_CLEAN`;
8. findings yield `COMPLETED_FINDINGS` and preserve raw evidence;
9. unavailable/skipped checks yield `INCOMPLETE`, never clean;
10. provider exception yields `FAILED`, never clean;
11. cancellation yields `CANCELLED`;
12. no automatic remediation authority exists;
13. full scan remains disabled;
14. Advanced details preserve provider provenance and raw evidence;
15. B6-0/B6-1/B6-2 predecessor tests remain green;
16. Qt offscreen smoke remains passive and overflow-free.

## Windows acceptance before checkpoint stabilization

B6-3 may be called implemented/CI-green after deterministic and Windows CI gates pass, but checkpoint stabilization additionally requires a real supported Windows run using an accepted live scan provider from the complete local source/runtime package. Required evidence:

- explicit user start;
- visible progress;
- harmless known fixtures only;
- correct zero-finding/findings/incomplete behavior;
- cancellation;
- no automatic quarantine/repair/destructive action;
- UI remains responsive;
- B6-2 visual/runtime-truth contract still green.

Until this real provider acceptance exists, the latest stable checkpoint remains unchanged.
