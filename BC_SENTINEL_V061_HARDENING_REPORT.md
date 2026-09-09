# BC Sentinel v0.6.1-beta.1 — Protection Service Hardening & Tamper Resistance Report

## A. Frozen baseline

Source baseline: **v0.6.0-beta.3 — Client Identity Fix**, natively accepted on Windows 11 on 2026-09-03.

User-supplied native freeze evidence for v0.6.0-beta.3:

- 211 development tests PASS;
- real `BCSentinelProtection` service RUNNING;
- `protection-client-identity-path = pass`;
- `protection-pipe-create = pass`;
- `protection-service-live = pass`;
- health `HEALTHY` over `windows_named_pipe`;
- 5,000-file acceptance `passed=true`, `critical_failures=[]`;
- final Windows benchmark: cold 42.27 files/s, warm 57.37 files/s, 4,950/5,000 warm cache hits, realtime synthetic CPU 21.78% of one core.

v0.6.1 deliberately preserves that Service ↔ Named Pipe ↔ GUI architecture and hardens the trust boundary around it.

## B. Primary risks found in the v0.6.0 deployment model

The audit found two high-value weaknesses to fix before adding more detection features:

1. the service could be installed directly from a frozen executable living under the developer/user Downloads tree, which is not an appropriate immutable service location;
2. the same `protection.secret` was used as both the user-readable IPC installation token and the HMAC key for privileged service configuration.

The latter meant secret separation was weaker than intended even though privileged IPC operations still required an authenticated administrator Windows token.

## C. Program Files deployment + ACL hardening

The v0.6.1 installer now:

- stops/deletes the previous service registration;
- deploys the complete PyInstaller onedir Protection Service image to:

  `%ProgramFiles%\BC Sentinel\Protection`

- applies an inheritance-restricted ACL:
  - LocalSystem: Full Control;
  - Administrators: Full Control;
  - Builtin Users: Read/Execute only;
- recursively removes stale child ACL inheritance from previous installs;
- keeps mutable state under `%ProgramData%\BCSentinel\Protection`;
- recursively removes legacy broad read grants from existing v0.6.x ProgramData children;
- grants the interactive installing user directory traversal plus read access only to the IPC token where required.

The installer no longer treats a user-writable Downloads tree as the canonical SCM binary location.

## D. Secret separation

v0.6.1 separates:

- `protection.secret` — IPC installation token, readable by the installing user for local status/control requests;
- `protection-integrity.key` — machine-private HMAC key used for service config integrity, install manifest authentication and audit chaining.

`protection-integrity.key` is restricted to SYSTEM/Administrators by the installer. Runtime ACL posture additionally treats untrusted read or write grants on this key as hardening failure.

A migration path accepts an existing v0.6.x config only if its legacy HMAC validates with the old IPC token; it is then re-signed with the new private integrity key. Invalid legacy configuration is not silently trusted or overwritten.

## E. Immutable install-tree integrity

The dedicated service build now embeds the rules directory and creates:

`dist\BC-Sentinel-Protection\protection-integrity.json`

The manifest contains SHA-256 + size for the complete frozen service tree (excluding the manifest itself and mutable build/runtime junk).

After deployment to Program Files, the elevated installer runs `seal-integrity`. The deployed executable:

1. verifies every manifest file once;
2. rejects missing, reparse-point, non-regular, size-mismatched or hash-mismatched protected files;
3. authenticates the manifest with the machine integrity key;
4. persists the manifest HMAC under protected ProgramData.

On sealed Windows startup, manifest failure prevents the protection runtime from declaring successful initialization.

Periodic self-protection checks use mtime, ctime, device/inode identity and size caching, with a forced complete content re-hash every tenth cycle. This avoids relying solely on size/mtime and explicitly addresses timestamp-restoration style evasion.

Unexpected executable/rule material (`.exe`, `.dll`, `.pyd`, `.sys`, `.py`, `.pyc`, `.yar`, `.yara`) and unexpected reparse points in the protected install tree are treated as tamper indicators.

## F. Runtime self-protection monitor

A new `BCS-SelfProtection` monitor runs while the service is alive. It checks:

- authenticated install manifest;
- protection configuration HMAC;
- install-tree ACL posture;
- ProgramData ACL posture;
- integrity-key ACL posture;
- SCM service binary path;
- SCM automatic-start configuration;
- SCM service account (`LocalSystem` expected);
- service recovery visibility (reported as posture metadata);
- service audit-chain integrity.

Tamper/drift changes `self_protection` to a critical failed component and degrades service health rather than falsely advertising full protection.

Importantly, operator suspension of realtime/behavior/network protection does **not** stop the self-protection monitor.

## G. SCM / recovery / lifecycle

The installer keeps conservative recovery configuration:

- restart after first failure: 5 seconds;
- restart after second failure: 15 seconds;
- failure counter reset: 24 hours;
- failure actions on non-crash failure enabled where supported.

The runtime now audits:

- SCM start;
- SCM stop request;
- runtime started/stopped;
- SCM stopped.

The service posture compares the registered SCM binary with the actually running frozen executable and reports changes.

## H. HMAC hash-chained audit

Privileged command audit and service lifecycle audit use an HMAC hash chain:

- each record includes the previous record HMAC;
- each record is authenticated with the machine integrity key;
- final chain state is stored separately under ProgramData;
- record editing, predecessor changes and tail truncation are detectable;
- a missing/corrupt chain state cannot silently reset an existing non-empty audit log.

Unsigned legacy v0.6 audit records are preserved as a separate legacy file during migration rather than mixed into the authenticated chain.

## I. UI behavior

The existing PySide6 design is preserved.

When the Protection Service is active but the hardening posture is not healthy, the UI now explicitly surfaces a degraded-integrity warning instead of presenting the service as unconditionally healthy.

No new visual redesign was introduced.

## J. Acceptance / performance tooling

`tools.windows_acceptance` now adds:

- `protection-hardening-foundation`;
- `protection-hardening-live` when `--service-live` is supplied.

The live hardening gate requires:

- sealed mode;
- authenticated manifest;
- config HMAC healthy;
- install/data/integrity-key ACL posture healthy;
- SCM posture healthy;
- audit chain healthy.

Additional tools:

### Service benchmark

`tools.service_hardening_benchmark`

Measures:

- service idle CPU/RSS;
- Named Pipe status request throughput;
- CPU impact during a benign temporary-file create/update/delete storm;
- final hardening posture.

### Reboot persistence acceptance

`tools.reboot_acceptance`

Two-stage `--arm` / `--verify` test validates a real Windows reboot occurred and then requires the automatically started service, Named Pipe and sealed hardening posture to be reachable.

## K. Development verification

Final development gate:

- **227/227 tests PASS**;
- `python -m compileall -q sentinel app tools` PASS;
- synthetic scanner benchmark (development/container, not comparable to native Windows):
  - cold: 2,234.59 files/s;
  - warm: 2,920.54 files/s;
  - 4,950/5,000 cache hits;
- synthetic integrity-engine benchmark, 1,000 × 256-byte protected files:
  - manifest build: ~0.058 s;
  - seal: ~0.115 s;
  - cached verify: ~0.052 s, 0 files re-hashed;
  - forced full verify: ~0.057 s, 1,000 files re-hashed.

These development numbers are not a substitute for the required native Windows service benchmark.

## L. Explicit limitations

v0.6.1 is still user-mode protection. It does **not** claim:

- Protected Process Light;
- kernel anti-tamper;
- protection against a hostile local administrator/SYSTEM/kernel actor;
- minifilter or WFP enforcement;
- signed installer/update publisher chain;
- guaranteed pre-execution blocking;
- automatic destructive containment.

A local administrator can ultimately replace/disable user-mode security components. v0.6.1 detects and prevents substantially more standard-user/config/install drift but does not pretend otherwise.

The polished one-action UAC broker was intentionally not rushed into this hardening release; privileged UI mutations remain fail-closed unless the calling client is elevated. A broker adds another privileged attack surface and should receive its own protocol/result-channel review.

## M. Native Windows freeze requirements

Do not freeze v0.6.1 until the target Windows system passes:

1. `227` tests;
2. hardened service build + manifest generation;
3. Program Files installation;
4. `sc.exe query BCSentinelProtection` → RUNNING;
5. 5,000-file `tools.windows_acceptance --service-live`;
6. `protection-hardening-foundation = pass`;
7. `protection-service-live = pass`;
8. `protection-hardening-live = pass`;
9. service hardening benchmark;
10. two-stage real reboot persistence acceptance.

## N. Recommended next release

**v0.6.2 — Privileged Action Broker + Upgrade/Repair Hardening** before signed updates/ransomware recovery.

Recommended scope:

- one-action UAC broker with nonce/expiry/strict operation schemas;
- safe result channel back to standard-user GUI;
- no arbitrary command execution;
- in-place service upgrade/repair and rollback policy;
- multi-user IPC token/access policy;
- additional Named Pipe fuzzing/rate limiting;
- service control DACL review.


## Beta.1 correction — Windows integrity cache timestamp restoration

Native Windows pytest exposed a real incremental integrity-cache bypass: Python `st_ctime_ns` on Windows represented creation time and therefore did not change when a protected file was rewritten with equal length and its mtime restored. The incremental verifier could consequently reuse a stale digest.

Beta.1 now obtains the kernel-maintained `FILE_BASIC_INFO.ChangeTime` through `GetFileInformationByHandleEx`. A cache entry is reusable only when a reliable change cookie is available and unchanged. If the native lookup fails, BC Sentinel re-hashes rather than trusting size/mtime. Native acceptance now includes a dedicated `protection-integrity-timestamp-evasion` probe reproducing the exact same-size/restored-mtime mutation.
