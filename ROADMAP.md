# BC Sentinel Roadmap

## Current status

**Frozen accepted line:** `v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening`

**Next development line:** `v0.10.0-beta.1 — Web Protection / Anti-Phishing / Anti-Scam Mature Expansion Foundation`

The v0.9 release-candidate completed native Windows acceptance on 2026-09-07. Its regression and safety boundaries are frozen and must remain green throughout v0.10 development.

## v0.9 — Antispyware & Advanced Antimalware

### v0.9.0-beta.1 — Antispyware & Persistence Detection Foundation

Native Windows accepted:

- Run/RunOnce and Startup discovery;
- Scheduled Tasks and automatic-service persistence inventory;
- WMI permanent persistence inventory;
- browser-policy/forced-extension inspection;
- proxy/DNS configuration inspection;
- Authenticode, target existence and user-writable-path evidence;
- persistent antispyware findings with provenance;
- conservative multi-signal correlation into Incident Engine;
- no automatic destructive persistence response.

### v0.9.0-beta.2 — Reversible Persistence Remediation & PUP/Adware Response

Native Windows accepted:

- HMAC-authenticated remediation plans;
- explicit approval gate for apply and restore;
- anti-race exact snapshot verification;
- reversible Run/RunOnce and selected browser-policy handling;
- Startup-item managed vault and exact restore;
- Scheduled Task disable/enable restoration;
- automatic-service start-mode change to manual without process termination, with restore;
- WMI/DNS/proxy remain review-only;
- bounded PUP/adware candidate evidence;
- interactive-user `HKEY_USERS` inventory while service runs as LocalSystem;
- protected IPC/UAC operations for apply and restore.

### v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation

Frozen into RC1:

- advisory `AdvancedAntimalwareEngine`;
- conservative PowerShell/script-host command analysis;
- bounded encoded/dynamic and in-memory execution indicators;
- LOLBin coverage for MSHTA, Rundll32, Regsvr32, Certutil, BITSAdmin, MSIExec, WMIC and CMSTP patterns;
- Office/browser/script-host parent-child context;
- same-PID temporal process→network correlation;
- deterministic file/IOC evidence fusion that may strengthen an existing behavioral chain;
- persistent explainable findings with evidence families, confidence, provenance and ATT&CK-style technique identifiers;
- read-only Protection Service status/findings surfaces.

### v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening

**NATIVE WINDOWS ACCEPTED / v0.9 FROZEN.**

Freeze evidence:

- Python regression: **482/482 PASS** on target Windows;
- dedicated RC1 false-positive gate: PASS;
- aggregate Windows foundation acceptance: PASS;
- native Protection Service/UAC/firewall build: PASS;
- upgrade acceptance and protected upgrade: PASS;
- live-service Windows acceptance: PASS;
- repair acceptance and protected repair: PASS;
- service-hardening benchmark: PASS;
- post-reboot live acceptance: PASS.

Frozen safety invariants:

- a single PowerShell/script/LOLBin process is not malware by identity;
- one evidence family cannot independently qualify HIGH;
- no broad command blocking solely from a LOLBin name;
- no automatic process termination from Advanced Antimalware;
- no automatic file deletion/quarantine from Advanced Antimalware;
- persistence mutation remains explicit-approval and reversible;
- rollback/recovery fails closed rather than silently weakening protection.

## v0.10 — Mature Web Protection, Anti-Phishing & Anti-Scam

### v0.10.0-beta.1 — Deception & Scam-Signal Foundation

Planned first milestone:

- build on the existing PID-scoped DNS/Web Protection architecture introduced in v0.7 rather than replacing it;
- richer explainable URL/domain deception evidence;
- mixed-script/IDN display-risk analysis;
- credential, payment/refund and prize/investment lure context only when combined with independent structural risk;
- nested-redirect and obfuscation context kept advisory;
- evidence-family/provenance output suitable for Security Center and incident correlation;
- signed domain/network IOC precedence remains authoritative;
- exact local domain trust remains bounded and revocable;
- all heuristic-only outcomes stay below HIGH and cannot auto-block;
- no HTTPS MITM, injected root CA, local TLS proxy or traffic decryption.

Later v0.10 betas may add safer browser-context collection, redirect-chain provenance, stronger signed threat-content integration and user-facing anti-scam explanations, subject to the same deterministic safety boundaries.

## Later macro-phases

- **v0.11** — EDR core and endpoint identity graph;
- **v0.12** — isolated sandbox and dynamic analysis;
- **v0.13** — IDS/IPS plus brute-force, password-spraying and credential-stuffing protection;
- **v0.14** — webcam/microphone privacy controls and Safe Banking;
- **v0.15** — identity protection, password vault and 2FA;
- **v0.16** — VPN and untrusted-network protection;
- **v1.0** — production endpoint-security suite after secure packaging, compatibility, operational and native-acceptance gates are complete.

## Invariants carried forward

- local-first deterministic protection;
- no cloud dependency for core protection;
- no private signing keys in distributions;
- no HTTPS MITM in the current Web Protection model;
- no heuristic-only destructive actions;
- BLOCK-only BC-owned firewall mutations;
- explicit privileged approval for reversible persistence mutation;
- dual-use administration tooling is not malware by identity alone;
- signed IOC evidence overrides weaker local heuristic/trust state where designed;
- rollback/recovery must fail closed rather than silently weaken protection.
