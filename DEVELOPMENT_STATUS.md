# BC Sentinel — Development Status

Current development candidate: **v0.10.0-beta.3 — Clone Site & Scam/Fraud Detection Expansion**.

## Current state
- Beta1 Web Reputation / Anti-Phishing foundation retained.
- Beta2 Reversible Web Response retained.
- Beta3 page-context clone-site and scam/fraud engine integrated into Protection Service protocol/status.
- Heuristic ceiling remains 49 and cannot auto-block.
- Signed IOC precedence, exact-domain trust and shared-IP/CDN safety remain unchanged.

## Local verification
543 passed, 2 Windows-native skipped, 0 failed. Beta1/Beta2/Beta3 local acceptance and compileall PASS.

## Windows acceptance contract
`TEST-V010-BETA3-ALL-NORMAL.bat` and `TEST-V010-BETA3-ALL-ADMIN.bat` each cover all required gates except reboot, including real upgrade/repair and standard-user -> UAC. Reboot remains intentionally deferred until final roadmap closure.

## Next
v0.10.0-rc.1 consolidation/adversarial hardening after Beta3 Windows acceptance is green.
