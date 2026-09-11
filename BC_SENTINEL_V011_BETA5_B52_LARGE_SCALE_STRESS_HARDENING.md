# BC Sentinel v0.11.0-beta.5 — B5-2 Large-Scale & Stress Hardening

## Purpose
B5-2 proves that the Rescue workflow remains bounded and read-only under technician-scale workloads. It does not add any new repair, quarantine, delete, registry, boot or execution authority.

Profile: `v0.11.0-beta.5-b52`

## Safety boundary
The stress probe:
- validates the offline target through the existing RR-6 target contract;
- refuses root symlink/reparse points before path resolution;
- skips descendant symlink/reparse entries;
- never executes target code;
- never writes to the target;
- never repairs, quarantines or deletes target content;
- never writes registry or boot state;
- requires output evidence to be outside the target;
- requires no network or cloud service.

## Hard resource ceilings
The implementation refuses configuration above:
- 200,000 files;
- 8 GiB total sampled-byte budget;
- 120 seconds elapsed budget;
- directory depth 256;
- 8 workers;
- 512 in-flight reads;
- 1 MiB sample per file.

Defaults are intentionally lower.

## Bounded concurrency
Reads use a bounded `ThreadPoolExecutor`. At any moment both the worker count and number of submitted in-flight reads are capped. Records are reassembled by deterministic sequence index so concurrency does not change result ordering.

## Large-file behavior
Large files are sampled up to `sample_bytes`; they are not loaded into memory in full. The result records both real file size and sampled bytes.

## Directory traversal
Traversal is iterative using an explicit stack rather than recursive Python calls. Depth is measured and bounded. Paths beyond the configured depth are pruned and counted, and any pruning makes the result explicitly partial rather than complete.

## Partial-result semantics
A partial run is never represented as a complete run.

Possible states:
- `COMPLETE` — bounded enumeration completed with no read/enumeration errors;
- `DEGRADED` — enumeration completed but read/enumeration errors were observed;
- `PARTIAL_FILE_LIMIT` — file budget reached;
- `PARTIAL_BYTE_LIMIT` — sample-byte budget reached;
- `PARTIAL_TIME_LIMIT` — elapsed-time budget reached;
- `PARTIAL_DEPTH_LIMIT` — configured traversal depth pruned one or more subtrees;
- `CANCELLED` — cancellation requested;
- `REFUSED` — preflight or contract failure.

## Performance metrics
Each completed/partial probe reports:
- elapsed milliseconds;
- files per second;
- sampled MiB per second;
- Python current and peak traced memory;
- configured worker/in-flight bounds;
- observed in-flight peak;
- maximum depth observed;
- read and enumeration errors;
- slow-read count.

The stable `probe_sha256` excludes volatile timing metrics and binds deterministic target/result content.

## Deterministic acceptance fixture
B5-2 deterministic acceptance creates:
- 12,000 bulk files;
- required Windows marker files;
- a 40-level deep directory chain;
- one 8 MiB file;
- a full read-only target hash snapshot before and after.

Acceptance thresholds:
- full state `COMPLETE`;
- at least 12,000 files probed;
- >= 40 depth observed;
- 8 MiB file sampled with 64 bytes only;
- throughput >= 100 files/s;
- Python traced peak <= 192 MiB;
- workers <= 4;
- observed in-flight <= 64;
- explicit file-limit, time-limit, depth-limit and cancellation states;
- target byte-identical;
- no new mutation authority.

## Windows gate
`TEST-V011-BETA5-B52.ps1` runs:
1. compileall for B5-2;
2. full Beta3 + Beta4 + B5-0..B5-2 pytest regression;
3. all deterministic predecessor acceptances;
4. deterministic B5-2 stress acceptance;
5. a live CLI fixture with 1,500 additional files;
6. target before/after SHA-256 verification;
7. service-registration check;
8. protected B2 source verification.

Expected cumulative pytest count: **239 tests**.

## Acceptance rule
B5-2 must not be frozen unless the authoritative non-elevated Windows gate is completely green. Performance or safety thresholds must not be weakened merely to obtain PASS.
