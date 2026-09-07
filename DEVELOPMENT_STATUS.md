# BC Sentinel Development Status

## Current

**v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening**

Status: **NATIVE WINDOWS ACCEPTED / v0.9 FROZEN**.

Target-machine verification completed on Windows on 2026-09-07:

- pytest: **482 passed / 482 executed**;
- v0.9 RC1 acceptance: **PASS**;
- aggregate Windows foundation acceptance: **PASS**;
- native Protection Service/UAC/firewall build: **PASS**;
- upgrade acceptance and protected upgrade: **PASS**;
- live-service Windows acceptance: **PASS**;
- repair acceptance and protected repair: **PASS**;
- service-hardening benchmark: **PASS**;
- post-reboot live acceptance: **PASS**;
- release SHA-256: `8a4a2c3e1cc7c9c411d7e25c189d016b29994311a4d991caba30dfa5bc23b350`.

No protection threshold or accepted destructive-action boundary was weakened to obtain the RC1 freeze.

## Frozen baseline

- `v0.8.0-rc.1 — Consolidation & Release Hardening`: **NATIVE WINDOWS ACCEPTED**.
- `v0.9.0-beta.1 — Antispyware & Persistence Detection Foundation`: **NATIVE WINDOWS ACCEPTED**.
- `v0.9.0-beta.2 — Reversible Persistence Remediation & PUP/Adware Response`: **NATIVE WINDOWS ACCEPTED**.
- `v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation`: **REGRESSION FROZEN INTO RC1**.
- `v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening`: **NATIVE WINDOWS ACCEPTED**.

The v0.7 firewall/Web Protection, v0.8 signed-threat/update-channel and v0.9 antispyware/remediation/advanced-antimalware safety invariants remain mandatory regression requirements.

## RC1 freeze guarantees

- benign PowerShell, CertUtil, MSIExec and BITSAdmin administrative scenarios stay below HIGH;
- Office/browser → PowerShell evidence remains bounded unless independent evidence converges;
- strong multi-signal chains remain HIGH/CRITICAL;
- no automatic process termination from Advanced Antimalware;
- no automatic file deletion/quarantine from Advanced Antimalware;
- persistence mutation remains explicit-approval and reversible;
- heuristic-only Web Protection remains non-destructive;
- HTTPS MITM remains disabled.

## Next

Development proceeds to **`v0.10.0-beta.1`**, the first milestone of the mature Web Protection, Anti-Phishing & Anti-Scam expansion. The v0.9 RC1 baseline is frozen and must remain green throughout v0.10 development.
