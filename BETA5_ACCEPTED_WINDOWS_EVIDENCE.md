# BC Sentinel v0.11.0-beta.5 — Accepted Windows Evidence

## Status

**CLOSED / PASS / FROZEN**

This document records the authoritative Windows acceptance evidence for Beta5 Real-World Rescue Hardening. It is documentation only and does not change any accepted runtime code, safety boundary, mutation authority, threshold, or predecessor checkpoint.

## Frozen final checkpoint

```text
checkpoint/v011-beta5-b57-pass
16676519e3e43d9916e5e4281813bd75c9eebd7e
```

The final B5-7 branch was tested from the pinned implementation commit `938340da0565193c535c070879c6d4998f0db702`; the frozen checkpoint also includes the bootstrap used to retrieve that exact implementation.

## Final portable technician artifact

```text
dist\Rescue\BC-Sentinel-Technician-Portable\BC-Sentinel-Technician-Portable.exe
SHA256=a35d61f1db187f1e1156851b2c8c23b837cdfd754d955f97a23dd588b33bac74
Build mode=PyInstaller onedir
PyInstaller=6.22.2
Build attempt=1/3 PASS
```

The built artifact remained portable and required no installer, Windows service, or driver.

## Accepted command surface

The final technician dispatcher exposes only the accepted Beta4/Beta5 workflows:

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

The final launcher does **not** expose `repair-execute`, `unlock`, `format`, `reimage`, `quarantine-execute`, or equivalent automatic destructive commands.

## Final Windows gate

The B5-7 bootstrap reran the complete accepted B5-6 predecessor chain before the final release checks.

Final B5-7 results:
- B5-6 predecessor gate: PASS;
- 20 B5-7 tests: PASS;
- deterministic dispatcher acceptance: PASS;
- portable status contract: PASS;
- forbidden command refusal: PASS;
- PyInstaller onedir build: PASS on first attempt;
- built `plan`: PASS;
- built `scan`: PASS;
- built `discover`: PASS with one READY offline fixture;
- built `assess`: PASS with `HEALTHY` state;
- built `stress`: PASS with `COMPLETE` state;
- built `resume init`: PASS;
- `decide` and `report` component loading: PASS;
- live target files tested: 203;
- target before/after: byte-identical;
- no Windows service registered;
- protected B2 service/realtime/EDR sources unchanged;
- no new mutation authority added.

Final B5-7 live output included:

```text
B57 TECHNICIAN RELEASE SHA256=a35d61f1db187f1e1156851b2c8c23b837cdfd754d955f97a23dd588b33bac74
B57 LIVE TARGET FILES=203 DISCOVER_READY=1 ASSESS=HEALTHY STRESS=COMPLETE
BC SENTINEL v0.11.0-beta.5 B5-7 PORTABLE TECHNICIAN RELEASE - PASS
BC SENTINEL v0.11.0-beta.5 B5-7 BOOTSTRAP - PASS
```

## B5-6 accepted controlled real-PC evidence

Frozen checkpoint:

```text
checkpoint/v011-beta5-b56-pass
7c86e087f0fe7769bf752889de82660a9c4c98f4
```

Authoritative Windows acceptance:
- 16 B5-6 tests PASS;
- `REAL_HARDWARE=1`;
- `CONTROLLED_FIXTURE=5`;
- `PROBLEMATIC_PC=NOT_RUN`;
- real Windows host control PASS;
- damaged / persistence / bounded-resource / locked-refusal / interrupted-resume controlled scenarios PASS;
- fixtures remained explicitly labeled and were not represented as real hardware;
- no repair/quarantine/unlock/format/reimage authority added;
- no service;
- B2 protected sources unchanged.

A genuine problematic-PC field case was intentionally not fabricated. Its standard-gate state remains `NOT_RUN`.

## Frozen Beta5 checkpoints

```text
B5-0  checkpoint/v011-beta5-b50-pass  385ba83a483f6a894dd7048cc2d3cec9c11e3a8e
B5-1  checkpoint/v011-beta5-b51-pass  32bce8ccdeb65c266ef651a1dfb0849950d0f0e5
B5-2  checkpoint/v011-beta5-b52-pass  d490f91aa16a5a2ae6f4660669f651619f1dd7b1
B5-3  checkpoint/v011-beta5-b53-pass  3d7566b78a636327c103602d418ec1ece37979bc
B5-4  checkpoint/v011-beta5-b54-pass  f93e7d044b96bac9e72a31ee131d9c37ab18367b
B5-5  checkpoint/v011-beta5-b55-pass  26bc2a365403658bb33881fb605101245cf87b5c
B5-6  checkpoint/v011-beta5-b56-pass  7c86e087f0fe7769bf752889de82660a9c4c98f4
B5-7  checkpoint/v011-beta5-b57-pass  16676519e3e43d9916e5e4281813bd75c9eebd7e
```

All checkpoint refs above are immutable acceptance references and must not be moved.

## Cumulative coverage

Beta5 acceptance grew milestone-by-milestone from the frozen Beta3/Beta4 rescue base:
- through B5-0: 212 cumulative tests covered;
- through B5-1: 226;
- through B5-2: 239;
- through B5-3: 255;
- through B5-4: 270;
- through B5-5: 285;
- through B5-6: 301;
- through B5-7: **321 cumulative tests covered**.

The final B5-7 gate reruns predecessor gates rather than reporting one monolithic `321 passed` line. The cumulative number reflects accepted predecessor coverage plus 20 B5-7 tests.

## Safety conclusion

Beta5 proves a field-hardened, portable technician workflow with explicit trust boundaries, bounded read-only discovery/assessment/stress behavior, safe resume semantics, advisory recovery decisions, technician evidence packaging, controlled real-host acceptance, and a validated portable Windows artifact.

Beta5 does **not** claim every infected or damaged PC can be recovered without reimage. Formatting/reimaging remains an allowed last-resort recommendation when integrity cannot be demonstrated. RR-6 recovery outcomes remain authoritative, and Beta5 never converts uncertainty or refusal into recovery success.
