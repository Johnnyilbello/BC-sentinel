# BC Sentinel v0.11.0-beta.4 — B4-4 Integrated Certification + Session Summary

## Purpose
B4-4 connects the accepted Beta4 orchestration evidence to the frozen RR-6 certification engine and emits one session-level outcome without weakening RR-6 trust semantics.

B4-4 adds no target mutation authority.

## Final outcomes
The Console exposes exactly the RR-6 result classes:

- `RECOVERED`
- `NOT_RECOVERED`
- `INDETERMINATE_REFUSED`

A refused/indeterminate result must never be translated into success.

## Pre-RR6 session trust gate
Before invoking RR-6, B4-4 validates continuity of the Beta4 session:

- B4-0 session plan exists and matches the current target fingerprint;
- B4-0 safety contract still proves read-only/no automatic execution;
- RR-3 evidence is still `TRUSTED` under B4-1 validation;
- if a B4-2 handoff is supplied, it must match the same target fingerprint and exact trusted scan SHA-256;
- a supplied repair transaction requires a B4-2 handoff and must match the exact RR-4B plan SHA-256;
- accepted repair transaction states are only `applied` or `rolled_back`;
- if a B4-3 summary is supplied, it must match the same target fingerprint and scan SHA-256;
- if B4-3 executed data rescue, the RR-5 manifest SHA-256, source root and error-free summary are revalidated;
- baseline, provenance, repair transaction and all outputs remain outside the offline target.

If this session trust gate fails, B4-4 returns `INDETERMINATE_REFUSED` and does **not** invoke RR-6.

## RR-6 delegation
When session continuity is trusted, B4-4 invokes the frozen RR-6 engine using:

- trusted RR-3 scan;
- approved critical baseline;
- approved provenance;
- optional accepted repair transaction.

B4-4 preserves RR-6 outcome, refusal reasons and not-recovered reasons exactly.

Trust failures inside RR-6 continue to take precedence over positive findings, as already frozen in RR-6.

## Session summary
B4-4 writes `b44-session-summary.json` containing:

- Beta4 profile/schema;
- session ID and correlation ID;
- target fingerprint;
- final outcome and `certified_recovered` state;
- whether RR-6 was invoked;
- RR-6 report path/hash when available;
- session-level refusal reasons;
- RR-6 refusal and not-recovered reasons;
- SHA-256 bindings for B4-0 plan, RR-3 scan, critical baseline, provenance, optional B4-2 handoff, optional repair transaction, optional B4-3 summary and RR-5 manifest;
- read-only safety flags;
- deterministic `summary_sha256`.

## Safety invariants
B4-4 must not:

- execute target files;
- run repair;
- delete target files;
- write registry or boot state;
- quarantine automatically;
- isolate the host;
- suppress reimage/format when trust cannot be established;
- create Windows services or drivers.

The offline target must remain byte-identical during B4-4.

## Logging
Critical decisions are recorded in `b44-audit.jsonl` with:

- session/correlation ID;
- target fingerprint;
- stage;
- status;
- exact reason;
- elapsed time;
- hashes and component-presence state where relevant.

Session-trust refusal and RR-6 refusal are distinguishable in logs and summary output.

## Acceptance requirements
B4-4 is accepted only if the Windows gate proves:

1. full Beta3 + B4-0..B4-4 pytest regression PASS;
2. all predecessor deterministic acceptance gates PASS;
3. B4-4 clean session -> `RECOVERED`;
4. trusted unresolved IOC -> `NOT_RECOVERED`;
5. session-binding failure -> `INDETERMINATE_REFUSED` before RR-6;
6. RR-6 provenance/trust failure -> `INDETERMINATE_REFUSED` from RR-6;
7. summary hash is self-consistent;
8. RR-6 report binding is valid;
9. target unchanged;
10. no service registration;
11. B2 protected service/realtime/EDR sources unchanged;
12. final B4-4 core and bootstrap PASS.

Only then may `checkpoint/v011-beta4-b44-pass` be created.
