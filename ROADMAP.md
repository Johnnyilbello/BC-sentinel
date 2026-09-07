# BC Sentinel Roadmap

## Current status

**Current development line:** `v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation`

The v0.8 supply-chain/signed-threat-intelligence macro-phase reached `v0.8.0-rc.1` and completed native Windows acceptance. v0.9 Beta1 and Beta2 are accepted baselines; Beta3 is the current native-acceptance candidate.

## v0.9 — Antispyware & Advanced Antimalware

### v0.9.0-beta.1 — Antispyware & Persistence Detection Foundation

Implemented and native Windows accepted:

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

Implemented and native Windows accepted:

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

**Current candidate — ready for native Windows acceptance.**

Implemented:

- advisory `AdvancedAntimalwareEngine`;
- conservative PowerShell/script-host command analysis;
- bounded encoded/dynamic and in-memory execution indicators;
- LOLBin coverage for MSHTA, Rundll32, Regsvr32, Certutil, BITSAdmin, MSIExec, WMIC and CMSTP patterns;
- Office/browser/script-host parent-child context;
- same-PID temporal process→network correlation;
- deterministic file/IOC evidence fusion that may strengthen an existing behavioral chain;
- persistent explainable findings with evidence families, confidence, provenance and ATT&CK-style technique identifiers;
- read-only Protection Service status/findings surfaces;
- dedicated `antimalware-v090-beta3-*` Windows acceptance gates.

False-positive and response invariants:

- a single PowerShell/script/LOLBin process is not malware by identity;
- one evidence family cannot independently qualify HIGH;
- no broad command blocking solely from a LOLBin name;
- no automatic process termination;
- no automatic file deletion/quarantine from this module;
- no automatic persistence mutation;
- existing Threat Decision, quarantine and reversible-remediation boundaries remain authoritative.

Development verification on the exact extracted release tree: `477 passed, 1 Windows-only skipped`; `compileall` PASS.

### v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening

Next planned milestone:

- consolidate Beta1–Beta3 regression requirements;
- false-positive hardening across administrative/script-heavy workloads;
- clean install / upgrade / repair matrix;
- persistence-remediation rollback/recovery matrix;
- Windows-native acceptance and performance regression;
- release/packaging hardening before closing v0.9.

## Later macro-phases

- **v0.10** — mature Web Protection, anti-phishing and anti-scam protection;
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
- rollback/recovery must fail closed rather than silently weaken protection.
