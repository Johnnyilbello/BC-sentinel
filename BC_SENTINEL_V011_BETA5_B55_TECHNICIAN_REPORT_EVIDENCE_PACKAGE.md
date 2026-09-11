# BC Sentinel v0.11.0-beta.5 — B5-5 Technician Report & Evidence Package

## Purpose
B5-5 turns already-produced Rescue evidence and the accepted B5-4 advisory decision into a portable technician evidence package. It is an export/reporting milestone only: it does not repair, quarantine, restore, rescue additional data, format, reimage, execute target code, or modify the offline target.

Profile: `v0.11.0-beta.5-b55`

## Frozen predecessor
B5-5 starts only from the accepted B5-4 checkpoint:

```text
checkpoint/v011-beta5-b54-pass
f93e7d044b96bac9e72a31ee131d9c37ab18367b
```

RR-6/B4-4 remains authoritative for certification. B5-4 remains advisory. B5-5 may report those results but cannot reinterpret or override them.

## Package layout
A successful build creates an external package directory containing:

```text
technician-report.json
technician-report.md
evidence-index.json
package-manifest.json
evidence/
```

The package directory must be outside the target. An existing non-empty package directory is refused.

## Input trust
Mandatory input:
- a B5-4 decision JSON bound to the exact offline target fingerprint.

The B5-4 decision is revalidated before export:
- expected profile/schema;
- allowed advisory state;
- internal `decision_sha256`;
- advisory-only safety flags;
- exact target fingerprint.

Every B5-4 evidence-index item marked trusted must still:
- exist outside the target;
- be a regular non-reparse file;
- match its exact SHA-256 binding.

A trusted evidence item that has drifted, disappeared or become a symlink/reparse point fails the package build closed.

## Untrusted evidence
Evidence already marked untrusted by B5-4 is not silently promoted and is not copied into the trusted package evidence tree. It remains explicitly listed in `evidence-index.json` and is surfaced in the technician report as an unresolved risk/refusal.

This preserves provenance without representing untrusted material as verified evidence.

## Reparse / path hardening
B5-5 checks decision, package and trusted-evidence paths for symlink/reparse state before path resolution. Package verification also checks each manifest-listed file before resolution and flags reparse substitutions or unlisted reparse objects.

This prevents a later symlink/junction substitution from being normalized away before verification.

## Evidence copying
Trusted evidence is copied using a temporary file and atomic replace. The copied bytes are hashed before finalization and must equal the source SHA-256 already bound by B5-4.

Hard bounds:
- maximum 64 indexed evidence items;
- maximum 256 MiB per evidence file;
- maximum 1 GiB copied evidence package budget.

No network or cloud service is required.

## Technician report
`technician-report.json` contains:
- target fingerprint;
- RR-6 outcome and certification flag;
- B5-4 advisory state;
- B5-4 decision reasons;
- recommended next action;
- signals from the B5-4 decision;
- unresolved risks/refusal reasons;
- data-rescue summary when present;
- evidence counts;
- safety contract;
- stable `report_sha256`.

`technician-report.md` presents the same operational outcome in human-readable technician form.

## Evidence index
`evidence-index.json` records for each item:
- logical label;
- original source path;
- package-relative path when copied;
- trust state;
- copy state;
- size;
- SHA-256;
- reason/status.

It has a stable `index_sha256` and includes the validated B5-4 decision itself as packaged evidence.

## Package manifest
`package-manifest.json` binds:
- target fingerprint;
- report SHA-256;
- evidence-index SHA-256;
- B5-4 decision SHA-256;
- every package file path, size and SHA-256 except the manifest itself;
- the report safety contract.

The manifest has its own stable `manifest_sha256` excluding volatile timestamp data.

## Verification
`verify_package()` and the CLI `verify` command check:
- manifest schema/profile and internal hash;
- path traversal/escape;
- duplicate paths;
- missing files;
- file size drift;
- SHA-256 drift;
- reparse/symlink substitution;
- unexpected/unlisted package files.

Any mismatch produces a failed verification. Verification never attempts repair.

## CLI
Build:

```text
python -m sentinel.rescue_technician_report build --target-root <offline-root> --decision <b54-decision.json> --package-dir <external-package-dir>
```

Verify:

```text
python -m sentinel.rescue_technician_report verify --package-dir <external-package-dir>
```

## Safety contract
B5-5:
- writes only to the external package destination;
- leaves the offline target byte-identical;
- never executes target content;
- never executes repair or rollback;
- never executes quarantine;
- never performs additional data rescue;
- never formats or reimages;
- never writes registry or boot state;
- adds no mutation authority;
- installs no service or driver.

## Tests
15 dedicated B5-5 tests cover:
- successful trusted package build/verification;
- target byte identity;
- package-inside-target refusal;
- decision-inside-target refusal;
- tampered decision refusal;
- target fingerprint mismatch;
- trusted source drift refusal;
- untrusted evidence preserved but not copied;
- source reparse refusal;
- non-empty destination refusal;
- packaged evidence tamper detection;
- unlisted extra-file detection;
- human report content;
- data-rescue summary and safety preservation;
- post-export manifest-listed reparse substitution detection.

Accepted B5-4 covers 270 cumulative tests. B5-5 therefore targets **285 cumulative tests covered**.

## Deterministic acceptance
The B5-5 acceptance fixture must prove:
- report JSON + Markdown produced;
- evidence index produced;
- package manifest produced;
- trusted evidence copied with exact SHA-256;
- one deliberately untrusted item remains untrusted and is not copied;
- RR-6 outcome and B5-4 advisory state are preserved;
- data-rescue counts are carried into the report;
- tampered exported evidence is detected;
- trusted source drift before export is refused;
- target remains byte-identical;
- all report safety flags remain non-mutating.

## Windows gate
`TEST-V011-BETA5-B55.ps1`:
1. reruns the complete accepted B5-4 predecessor gate;
2. compile-checks B5-5;
3. runs all 15 B5-5 tests;
4. runs deterministic B5-5 acceptance;
5. creates a persistent live fixture;
6. invokes package `build` in a separate process;
7. invokes package `verify` in a separate process;
8. verifies report/manifest/index hashes and preserved RR-6/B5-4 outcomes;
9. verifies the target is byte-identical;
10. verifies no Windows service and protected B2 sources unchanged.

## Acceptance rule
B5-5 is frozen only after the authoritative non-elevated Windows gate is fully green. No trust rule, tamper check, predecessor gate or safety boundary may be weakened merely to obtain PASS.
