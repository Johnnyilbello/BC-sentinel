# BC Sentinel v0.10.0-beta.3 — UAC Harness FIX1

Date: 2026-09-08

Observed Windows evidence before FIX1:
- full Beta3 suite: 545 passed;
- admin targeted phase: 115 passed;
- Protection Service/Broker builds: passed;
- same-version upgrade rejection: expected anti-downgrade behavior;
- real same-version repair: passed;
- Beta1/Beta2/Beta3 service-live acceptance: passed;
- Windows native acceptance and service benchmark: passed;
- final standard-user -> UAC gate: failed because the helper remained elevated (`is_admin=true`).

Root cause is isolated to the ADMIN test harness de-elevation path. `Shell.Application.ShellExecute` is not a reliable guarantee of a medium-integrity child from an elevated PowerShell on every Windows build.

FIX1 changes only the acceptance harness: it locates Explorer in the current interactive session, duplicates Explorer's filtered primary token, and launches the existing standard-user helper through `CreateProcessWithTokenW`. The helper still fails closed unless it independently observes `is_admin=false`. No product protection logic or security policy was weakened.

Reboot remains deferred until final roadmap acceptance.
