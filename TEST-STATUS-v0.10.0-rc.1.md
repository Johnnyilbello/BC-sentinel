# Test Status — v0.10.0-rc.1

Status: **RC1 candidate ready for Windows acceptance; not final-accepted yet**.

## Local pre-delivery
- 547 passed
- 2 skipped (Windows-native only in the non-Windows build environment)
- 0 failed
- targeted Beta2/Beta3/RC1: 28 passed
- compileall PASS
- Beta1 local acceptance PASS
- Beta2 local acceptance PASS
- Beta3 local acceptance PASS
- RC1 consolidation local acceptance PASS
- benign/enterprise compatibility matrix: 323 checked, 0 failures
- local performance gate PASS

## Mandatory Windows RC1 gates
Both master launchers include all gates except reboot:
1. full regression;
2. targeted native/security + RC1 consolidation tests;
3. fresh Protection Service + UAC Broker build;
4. real upgrade from installed Beta3 when older, or correct same-version anti-downgrade rejection after RC1 is already installed;
5. real same-version repair;
6. Beta1/Beta2/Beta3 service-live acceptance;
7. RC1 consolidation service-live acceptance and IPC latency check;
8. Windows native acceptance + performance benchmark;
9. service hardening benchmark;
10. true standard-user -> UAC one-action broker acceptance.

## Deliberately excluded
- reboot persistence/recovery: deferred until final roadmap acceptance.

Do not mark RC1 Windows accepted until one of the packaged master launchers completes all listed gates successfully.
