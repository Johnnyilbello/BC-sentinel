# BC Sentinel v0.7.1-beta.2 — Security Development Report

## Accepted baseline

The release is built on the user-validated native Windows v0.7.1-beta.1 baseline:

- 319/319 Windows tests passed;
- transactional upgrade from v0.7.0-beta.3 succeeded;
- Protection Service remained RUNNING under LocalSystem;
- native firewall add/observe/remove baseline passed;
- external firewall disable drift was detected and explicitly reconciled;
- `tools.windows_acceptance --service-live` returned `passed=true` and `critical_failures=[]`.

The beta.2 work therefore does not redesign the accepted firewall boundary. It layers abuse resistance, conflict visibility and service-owned threat decisions on top.

## Security changes

### Request abuse controls

A local sliding-window limiter now bounds privileged mutation bursts per authenticated Windows identity/session. Invalid IPC traffic uses a separate limiter. These controls are deterministic and local-only.

### Policy conflict analysis

Firewall conflicts are read-only. Exact managed-group ownership failures are blocking posture findings. External ALLOW overlaps are advisories only and are never modified because Windows BLOCK precedence remains effective.

### Threat response boundary

Standard-user GUI file quarantine/delete no longer bypasses the privileged service when the service owns protection. The expected SHA-256 is carried through the protocol and revalidated at execution.

### Destructive-response safety

Permanent delete remains double-confirmed in the UI and manual-only. Service-side quarantine/delete are accepted only for qualified HIGH/CRITICAL detections with score >=70, are protected against BC Sentinel-managed paths and the protected Windows system tree, reject reparse points, and revalidate both file snapshot and SHA-256 identity immediately before mutation.

### Performance without weaker caching

The scanner avoids attempting PE parsing unless the bytes begin with `MZ`. No metadata-only verdict shortcut was introduced. Hash-cache acceleration therefore does not become a new timestamp-restoration bypass.

## Development gates

- legacy v0.7.0/v0.7.1 tests retained;
- new rate-limit/conflict/Threat Decision regression tests added;
- harmless Threat Decision acceptance added;
- Windows aggregate acceptance extended for beta.2 live posture.

## Final development evidence

- `331 passed, 1 skipped` on the non-Windows development host;
- `compileall` PASS;
- harmless Threat Decision acceptance PASS;
- beta.2 rate-limit/conflict/Threat Decision aggregate probes PASS;
- 2,000-file benchmark: cold 4,456.93 files/s, warm 5,581.14 files/s, warm speedup 1.252x, 99% hash-cache hit ratio;
- native Windows expected pytest count: **332 passed** before build/upgrade/live acceptance.
