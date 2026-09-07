# BC Sentinel v0.9.0-rc.1 — Test Status

## Final target-Windows result

Validation completed on 2026-09-07.

- Python regression: **482 passed / 482 executed**.
- RC1 local acceptance: **PASS**.
- Aggregate Windows foundation acceptance: **PASS**.
- Native Protection Service/UAC/firewall build: **PASS**.
- Upgrade acceptance: **PASS**.
- Protected transactional upgrade: **PASS**.
- Aggregate live-service Windows acceptance: **PASS**.
- Repair acceptance: **PASS**.
- Protected same-version repair: **PASS**.
- Service-hardening benchmark: **PASS**.
- Post-reboot live acceptance: **PASS**.

## False-positive hardening

- harmless PowerShell write/output: SAFE;
- signed Microsoft CertUtil hash operation: SAFE;
- signed Microsoft MSIExec remote-package fixture: SAFE;
- browser → PowerShell `-NoProfile` fixture: SAFE;
- BITSAdmin transfer-only fixture: SAFE;
- Office → PowerShell download-only fixture: bounded below HIGH;
- strong multi-signal fileless chain: HIGH;
- deterministic-qualified chain: CRITICAL;
- automatic process termination/delete/quarantine remains disabled.

## Freeze conclusion

All required RC1 gates passed on the target Windows environment. `v0.9.0-rc.1` is the frozen v0.9 regression baseline. Newer milestones must preserve these accepted safety and compatibility gates.
