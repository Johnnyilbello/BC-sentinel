# Internal offline Windows candidate — implementation in validation

This is not a stable release. Public stable remains unchanged. Clean Windows VM
installation/uninstallation, a frozen scan across two real volumes, and dedicated
lab evidence are outstanding. No superiority claim is authorized.

## Operator workflow

Open “Scansione offline” in the desktop sidebar, choose the offline Windows root
and a report folder on another local volume. Optionally select an approved local
SHA-256 catalog and YARA source. Without them only structural/heuristic analysis
is available. Progress, cancellation, detections, review items, errors and skipped
files are displayed. The examined files are never executed or remediated.

CLI: `python -m sentinel.rescue_offline_scanner --root E:\ --output C:\Reports\Run1`
with optional `--intel-catalog`, `--yara-rules`, `--max-files`, `--max-file-bytes`,
`--max-total-bytes`, `--max-seconds`, `--max-rss-bytes`.
Exit codes: 0 completed selected scope, 3 incomplete, 2 validation/runtime failure.
Ctrl+C requests cancellation and persists an incomplete report. The windowed
package accepts `--offline-root`, `--offline-output`, `--intel-catalog` and
`--yara-rules`; its report is the automation result rather than console output.

## Coverage and limits

Only supported executable/script extensions in System32, SysWOW64, startup and
user temp locations are scanned; this is not every file on the volume. Hive hashes
are identity evidence, not a malware verdict. An observed file is never called
clean. Reports identify incomplete reads, skipped sizes, resource stops, unavailable
YARA, unstable files and traversal omissions.

Default limits: 10,000 candidates, 64 MiB/file, 1 GiB selected content including
hashed hives, 600 seconds, 1 GiB process RSS. Time/RSS enforcement is cooperative;
it is checked between operations and hash chunks. Native PE/YARA operations and
blocked OS reads cannot yet be forcibly interrupted. YARA matching has a two-second
timeout and bounded input. This remaining limitation prevents a hard real-time or
hard memory isolation guarantee. The total byte budget describes selected content,
not cumulative I/O from repeated integrity reads.

Local paths are checked for junctions/symlinks and network drives. Desktop and CLI
require different physical filesystems for target and reports. In-process legacy
fixture tests explicitly disable only that volume check for harmless tmp directories;
production entry points offer no such switch. Adversarial path replacement between
checks is not a substitute for a genuinely read-only mounted target.

## Packaging and evidence

`BUILD-V014-OFFLINE-CANDIDATE.ps1 -OutputRoot <new-directory> -PythonPath <python>`
uses installed dependencies without downloading them, requires committed source,
builds a portable onedir ZIP, and records commit and artifact hashes. Frozen startup,
UI smoke and same-volume refusal are exercised with disposable app data. These are
local package checks, not clean-VM installation/uninstallation evidence. The package
is unsigned and is for internal evaluation only.

## Historical tests

See `tests/historical/README.md`: 86 tests passed at their historical checkpoints;
three Beta1 modules still lack their historical dependencies. No test file was
deleted to create a green current-source gate.

## Real-sample and comparison gate

No real samples may run on a development machine or CI. The existing T3 gate must
first receive authorized Linux/KVM host preflight, harmless snapshot/revert proof,
and laboratory evidence. None is available for this candidate.

Before any benchmark, freeze and hash a corpus registration containing at least
200 authorized malicious samples and 200 benign files, each with SHA-256, category,
expected outcome, provenance and authorization. Freeze product commit/version,
Defender engine/signatures, hardware, OS image, offline/network settings, cache
condition, order randomization seed, timeout/error rules and raw report locations.
Both products receive equivalent copies restored from the same baseline. Perform
five runs per sample and condition; retain wall time, CPU time and peak RSS per
process tree. Missing/failed scans cannot be silently removed or counted clean.

The metadata-only `sentinel.offline_benchmark` evaluator checks paired five-run
records and corpus counts. It resamples paired files within each class, preserving
within-file repetitions, and computes five one-sided 99% lower bounds (Bonferroni
familywise 95%). BC advantage must be strictly positive in sensitivity, false
positive rate, seconds/file, CPU seconds/file and peak RSS/file. Ties fail. Bootstrap
uncertainty is an estimate, not proof of representativeness. Independent evidence
review must verify preregistration and comparability; the tool never authorizes a
public claim. Synthetic metadata tests do not constitute a benchmark against Defender.
