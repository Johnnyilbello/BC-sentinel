# BC Sentinel v0.10.0-beta.2 — Test Status

## Packaging-side validation
- full pytest regression: **532 passed, 2 skipped, 0 failed** (the two skips are Windows-native gates unavailable in the packaging environment);
- targeted Beta2 + Beta1 + legacy Web Response regression: PASS;
- v0.10 Beta1 deception/reputation local acceptance: PASS;
- v0.10 Beta2 reversible Web Response local acceptance: PASS;
- legacy reversible Web Response local acceptance: PASS;
- Python compileall: PASS.

## Beta2 acceptance matrix — local
- signed IOC -> temporary containment: PASS;
- duplicate-rule prevention: PASS;
- manual rollback: PASS;
- signed IOC overrides older exact local trust: PASS;
- heuristic-only -> no address block: PASS;
- shared/CDN IP guard: PASS;
- same-PID DNS + observed connection revalidation: PASS;
- TTL expiry: PASS;
- restart recovery: PASS;
- stale-rule cleanup: PASS;
- heuristic policy fail-closed: PASS.

## Windows status
Not accepted yet. Run the two supplied all-in-one commands. The elevated script builds and installs the current Protection Service/UAC Broker, runs Beta1 and Beta2 service-live acceptance, the legacy web-response live regression, Windows acceptance and the service-hardening benchmark. Upgrade/repair/reboot and a real standard-user -> UAC flow remain separate historical gates and are not marked PASS by Beta2.
