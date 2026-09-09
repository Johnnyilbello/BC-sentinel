# BC Sentinel v0.9.0-rc.1 — Test Status

## Local regression baseline

Environment used for the cross-platform release-candidate audit: Linux runner, Python 3.13.5. The product target remains Windows.

- `pytest -q`: **481 passed, 1 skipped**.
- `python -m compileall -q app sentinel tools tests`: **PASS**.
- v0.9 RC1 local acceptance: **PASS**.
- Historical cross-platform acceptance gates re-run on RC1: **14/14 PASS**.
- No protection threshold or previously accepted destructive-action boundary was weakened.

## v0.9 RC1 false-positive hardening

- harmless PowerShell write/output: SAFE;
- signed Microsoft CertUtil hash operation: SAFE;
- signed Microsoft MSIExec remote-package fixture: SAFE;
- browser → PowerShell `-NoProfile` fixture: SAFE;
- BITSAdmin transfer-only fixture: SAFE;
- Office → PowerShell download-only fixture: SUSPICIOUS but bounded below HIGH;
- strong multi-signal fileless chain: HIGH;
- deterministic-qualified chain: CRITICAL;
- automatic process termination/delete/quarantine remains disabled.

## Synthetic performance smoke

These figures are runner-local smoke measurements, not Windows release SLAs.

- scanner: 250 synthetic files completed in cold and warm passes; warm hash-cache hit ratio 0.988;
- behavioral correlation: 5,000 synthetic events completed, 975 correlated;
- network intelligence: 1,000 synthetic events persisted and correlated;
- realtime benchmark used the direct-pipeline fallback because the runner is not Windows.

## Windows-native gates still required before freeze

The following cannot be considered passed from a Linux runner and must execute on the target Windows machine:

- aggregate `tools.windows_acceptance` foundation gate;
- aggregate `tools.windows_acceptance --service-live` gate;
- Protection Service/UAC broker live checks;
- Windows Firewall foundation/drift/containment checks;
- native ETW/watchdog/AuthentiCode checks;
- update acceptance in upgrade mode;
- update acceptance in repair mode after the protected install is on RC1;
- reboot persistence arm → reboot → verify;
- service-hardening benchmark.

The RC must not be declared frozen until the native Windows aggregate reports zero critical failures.
