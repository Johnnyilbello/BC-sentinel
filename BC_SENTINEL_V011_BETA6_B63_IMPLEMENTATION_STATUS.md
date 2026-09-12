# BC Sentinel v0.11.0-beta.6 — B6-3 Implementation Status

Status: **B6-3.0 ORCHESTRATION FOUNDATION CI GREEN / B6-3.1 LIVE PROVIDER BOUNDARY CI GREEN / COMPLETE WINDOWS RUNTIME ADAPTER PENDING**

Development branch: `feature/v011-beta6-b63-smart-scan`

## Product-owner decision

Further UI polishing is intentionally deferred. Functional/security roadmap work continues first. The accepted B6-2 Dashboard visual contract remains the UI baseline and must not regress.

## B6-2 predecessor

B6-2 Home / Security Overview is automated-Windows-CI green, including responsive geometry and runtime-truth checks. Manual product-owner visual acceptance and additional polish remain open, so B6-2 has not replaced B6-0 as the latest stable checkpoint.

## B6-3.0 — Smart Scan orchestration foundation

Implemented:

- typed Smart Scan plan/check/finding/progress/result models;
- explicit session states: `IDLE`, `PLANNED`, `RUNNING`, `COMPLETED_CLEAN`, `COMPLETED_FINDINGS`, `INCOMPLETE`, `FAILED`, `CANCELLED`;
- complete-vs-incomplete coverage semantics;
- provider capability contract and provenance;
- explicit user start only;
- duplicate-start refusal;
- cancellation;
- monotonic bounded progress;
- Qt worker-thread integration so scan work does not run on the GUI thread;
- one shared Smart Scan coordinator for Dashboard, sidebar and Scansione page;
- Advanced details preserve complete result/evidence payload;
- Full Scan remains disabled;
- no automatic quarantine, repair, process termination, file deletion, registry/boot write, unlock, write mount, format or reimage authority.

Deterministic provider fixtures prove clean, findings, incomplete, failed and cancelled outcomes. `CLEAN` cannot be produced when planned coverage is missing.

## B6-3.1 — Live provider boundary

Implemented fail-closed loader:

```text
sentinel.smart_scan_provider_loader
```

The Home looks only for the fixed adapter module:

```text
sentinel.smart_scan_live_provider
```

with factory:

```text
create_provider()
```

Loader guarantees:

- importing/loading the adapter does not plan or run a scan;
- missing adapter fails closed;
- missing adapter dependency fails closed;
- missing/failing factory fails closed;
- available-but-unaccepted provider is rejected;
- provider requesting destructive authority is rejected;
- accepted provider may enable Smart Scan only after capability validation;
- no dynamic arbitrary plugin path is accepted.

The normal B6-3 Home now uses this loader automatically when no provider is explicitly injected. If the complete Windows source tree supplies a conforming `sentinel.smart_scan_live_provider`, Smart Scan can be enabled without changing the Home or weakening its authority contract.

## Why the real provider is not fabricated in GitHub

The synchronized GitHub repository is historically a delta tree rather than the complete Windows runtime source-of-record. The repository does not currently expose the complete live scanner API required to implement a truthful adapter. Existing historical/synchronized files refer to runtime components that are absent from the GitHub delta.

For that reason BC Sentinel deliberately reports the default provider as unavailable instead of inventing a scanner API or reusing the offline Rescue scanner as a live-PC scanner.

The optional adapter must be implemented against the complete local Windows source/runtime package and then synchronized back once its actual API is verified.

## Current automated evidence

Latest B6-3 Windows CI including the fail-closed live-provider loader:

- workflow: `B6-3 Smart Scan Gate`;
- run: `34710390958`;
- result: **PASS**;
- deterministic regression suite: **92 passed**;
- loader tests cover missing module, missing dependency, missing/failing factory, accepted provider, destructive-authority rejection and available-but-unaccepted rejection;
- B6-2 predecessor deterministic acceptance: PASS;
- B6-3 deterministic acceptance: PASS with zero failures;
- B6-3 passive self-check: PASS;
- Qt offscreen smoke: PASS;
- six-page Home shell preserved;
- Dashboard and Scan horizontal overflow: 0;
- default GitHub-delta provider load: `loaded=false`, `accepted=false`, reason `live_provider_module_not_synchronized`;
- Smart Scan remains disabled by default when that accepted live adapter is absent;
- Full Scan remains disabled;
- automatic destructive authority remains false.

## Next gate — complete local Windows runtime adapter

B6-3 is not complete and not stable until the complete local source/runtime supplies and proves `sentinel.smart_scan_live_provider`.

Required next evidence:

1. inspect the real full-runtime scanner/service API;
2. implement the adapter without changing the underlying scanner authority;
3. prove adapter capability metadata and exact scan scope;
4. explicit user start only;
5. visible real progress;
6. harmless known fixtures only;
7. correct clean/findings/incomplete/failure/cancel behavior;
8. no automatic remediation;
9. responsive UI during scan;
10. predecessor B6-0/B6-1/B6-2 gates remain green;
11. real supported Windows acceptance evidence committed before checkpoint stabilization.

## Stable state

Until those requirements pass, the latest accepted stable checkpoint remains:

```text
v0.11.0-beta.6 B6-0 — Technician UX Foundation
checkpoint/v011-beta6-b60-pass
stable/v011-beta6-b60
cf82b062ee8a95a116a449a0daf03bebd0b67cea
```
