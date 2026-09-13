# BC Sentinel v0.11.0-beta.6 — B6-3.4 Live Benchmark R2

Date: 2026-09-13
Status: **PASS — performance + live finding translation + complete declared Smart Scan coverage**

## Runtime

- provider profile: `v0.11.0-beta.6-b63.4-smart-scope`
- scope mode: `risk_prioritized_v1`
- guard: `exclude_pinned_runtime_root_v1`
- pinned historical scanner SHA-256: `7874df734f6146f8848d8a55f5eb6be37bb5cbaee1638e051357f978f5275433`
- `scan_file` probe: available
- full filesystem coverage claimed: **false**
- destructive/remediation authority: **false**

## Benchmark policy

- max files: 250
- max selected bytes: 128 MB
- max individual file: 64 MB
- recent window: 90 days

## Observed live result

- executed: true
- total checks: 5
- completed checks: 5
- coverage: `COMPLETE`
- state: `COMPLETED_FINDINGS`
- elapsed: **18,188 ms (~18.2 s)**
- no destructive authority: true
- acceptance evidence: `acceptance-v011-beta6-b634-benchmark-250-r2.json`

Selected files:
- Downloads: 0
- Desktop: 0
- Documents: 0
- AppData\\Local\\Temp: 221
- AppData\\Roaming: 29
- total: 250

The exact pinned historical runtime root was excluded before budget allocation, preventing the authoritative scanner's intentional self-managed-path refusal from turning the run into `INCOMPLETE`.

## Finding translation

The live historical `assessment` payloads were translated successfully into B6-3 findings. The result included controlled BC Sentinel test fixtures in Temp and a low-severity heuristic assessment for a Microsoft Edge temporary updater executable. This benchmark does **not** authorize automatic deletion, quarantine, repair, or process termination.

## Performance conclusion

The prior broad historical scan required roughly 86 minutes and behaved like a deep/full scan. The B6-3.4 bounded risk-prioritized plan completed its declared 250-file scope in about 18.2 seconds. This is not a whole-disk coverage comparison; it validates that Smart Scan is now a distinct bounded consumer scan rather than an accidental Full Scan.

## Gate impact

Closed by this run:
- real pinned Windows B6-3.4 performance benchmark;
- declared Smart Scan scope completion;
- live finding translation;
- runtime self-managed-path exclusion guard;
- no destructive authority.

Still open before B6-3 stabilization:
1. real cancellation during active pinned-runtime scanning;
2. UI responsiveness and visible progress during a real B6-3.4 scan;
3. final supported-Windows evidence/checkpoint consolidation;
4. predecessor gates must remain green.

Do not advance B6-4 until those remaining stabilization items are accepted.
