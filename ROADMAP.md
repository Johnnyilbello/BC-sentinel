# BC Sentinel Roadmap

## Current status

**Current development line:** `v0.9.0-beta.2`

The v0.8 supply-chain and signed-threat-intelligence macro-phase reached `v0.8.0-rc.1` and completed native Windows acceptance.

## v0.9 — Antispyware & Advanced Antimalware

### v0.9.0-beta.1 — Antispyware & Persistence Detection Foundation

Implemented:

- Run/RunOnce and Startup discovery;
- Scheduled Tasks and automatic-service persistence inventory;
- WMI permanent persistence inventory;
- browser-policy/forced-extension inspection;
- proxy/DNS configuration inspection;
- Authenticode, target existence and user-writable-path evidence;
- persistent antispyware findings with provenance;
- conservative multi-signal correlation into Incident Engine;
- no automatic destructive persistence response.

Status: dedicated native feature/service gate passed; aggregate freeze evidence was not supplied before moving to Beta2.

### v0.9.0-beta.2 — Reversible Persistence Remediation & PUP/Adware Response

Current release candidate.

Implemented:

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
- protected IPC/UAC operations for apply and restore;
- dedicated Windows acceptance gates.

Freeze requirement: native Windows `470 passed` plus `antispyware-v090-beta2-foundation`, `antispyware-v090-beta2-live` and aggregate `critical_failures=[]`.

### v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation

Planned:

- PowerShell/script behavior correlation;
- LOLBin/process-chain anomaly evidence;
- stronger credential-stealer and persistence-chain indicators;
- fileless execution evidence with conservative false-positive gates;
- signed reputation/YARA/process/network evidence fusion;
- no broad command blocking solely from a LOLBin name;
- stronger recovery/journal integration where technically safe.

### v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening

Planned:

- complete regression across v0.7/v0.8/v0.9;
- clean install / upgrade / repair matrix;
- false-positive and persistence-remediation rollback matrix;
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
- no HTTPS MITM in the present Web Protection model;
- no heuristic-only destructive actions;
- BLOCK-only BC-owned firewall mutations;
- explicit privileged approval for reversible persistence mutation;
- rollback/recovery must fail closed rather than silently weaken protection.
