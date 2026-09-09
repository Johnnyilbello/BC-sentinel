# BC Sentinel v0.10.0-beta.2 — Reversible Web Response / Blocking

## Scope
Beta2 adds the safe response layer to the Beta1 Web Reputation / Phishing foundation.

## Security invariants
- no heuristic-only address blocking;
- explicit operator approval for web containment;
- active signed IOC revalidation at action time;
- signed-domain response requires observed same-PID network + fresh DNS context;
- shared/CDN IP addresses are never address-contained by this path;
- temporary BC-owned rules only, bounded 60–3600 second TTL;
- idempotent duplicate requests and active-address lease reuse;
- manual release, automatic TTL expiry, conservative restart recovery and stale-rule cleanup;
- no MITM HTTPS, root CA, hosts-file broad mutation, global firewall-default changes, or origin-only destructive file/process action.

## Acceptance
Use TEST-V010-BETA2-ALL-NORMAL.bat from a normal PowerShell, then TEST-V010-BETA2-ALL-ADMIN.bat from an elevated PowerShell. Beta2 is not accepted until both complete successfully on Windows.
