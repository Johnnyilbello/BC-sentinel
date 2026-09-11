# BC Sentinel v0.11.0-beta.4 — B4-3 Guided Safe Data Rescue

## Purpose
B4-3 integrates the already accepted RR-5 Safe Data Rescue into the Beta4 Rescue Console while preserving explicit operator control and the source-read-only contract.

## Trust chain
B4-3 requires a B4-1 RR-3 scan that still validates as `TRUSTED`. The plan binds:
- current RR-6 target fingerprint;
- exact trusted RR-3 scan SHA-256;
- explicit `Users/<profile>` selections;
- destination path;
- RR-5 bounded limits;
- high-confidence hashes that must remain contained.

## Two-phase workflow
### Preview
Default behavior creates only:
- `b43-data-rescue-plan.json`;
- `b43-guided-data-rescue-summary.json`.

Preview does not create or populate the rescue destination and returns:
`operator_action_required=confirm_and_run_data_rescue`.

### Explicit execution
Only an explicit `--execute-rescue` request invokes the frozen RR-5 extraction engine.

## Data disposition
- passive allowlisted content -> `rescued-data/`;
- executables, scripts, macro documents, archives, unknown extensions -> `containment/`;
- exact deterministic IOC or YARA hashes already proven by the trusted RR-3 scan -> `containment/`;
- optional operator-approved RR-5 hash intel may be merged with those trusted scan hashes.

B4-3 never claims copied data is universally malware-free. It preserves RR-5 disposition semantics and provenance.

## Safety invariants
- source target remains read-only and byte-identical;
- selections remain explicit; no blind whole-disk extraction;
- source/destination overlap is refused;
- destination cannot contain the offline target;
- symlink/reparse protections remain inherited from RR-5;
- SHA-256 verification remains mandatory;
- no source execution or deletion;
- no registry or boot writes;
- no repair execution;
- no automatic restore to another host;
- no recovery certification;
- no service/driver installation;
- B2 protected service/realtime/EDR sources remain unchanged.

## Acceptance matrix
B4-3 must prove:
1. Beta3 + B4-0..B4-3 regression green;
2. all predecessor deterministic acceptances green;
3. preview produces no data copy;
4. empty or invalid selections are refused;
5. destination overlap is refused;
6. untrusted RR-3 evidence is refused;
7. explicit execution copies passive data into `rescued-data`;
8. high-confidence IOC executable is routed to `containment` and absent from clean tree;
9. RR-5 manifest SHA-256 is present;
10. source remains byte-identical;
11. no Windows service registration;
12. protected B2 sources remain unchanged.

## Logging
Critical B4-3 failures must expose stage, reason, session/correlation ID when available, target fingerprint, normalized source/destination paths, selection count, relevant limits and elapsed time. Diagnostic acceptance output may be verbose; production output remains structured.

## Freeze rule
B4-3 may be frozen only after the Windows gate ends with both:

```text
BC SENTINEL v0.11.0-beta.4 B4-3 GUIDED SAFE DATA RESCUE - PASS
BC SENTINEL v0.11.0-beta.4 B4-3 BOOTSTRAP - PASS
```

No acceptance threshold or RR-5 safety invariant may be weakened to obtain PASS.
