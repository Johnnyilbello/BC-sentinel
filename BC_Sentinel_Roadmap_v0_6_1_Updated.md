# BC Sentinel — Product & Security Roadmap

Current development line: **v0.6.1 Beta — Protection Service Hardening & Tamper Resistance**.

## Completed / frozen foundation

### v0.3.1 — Security Hardening
PID-reuse-safe identity, stronger ETW attribution, path/reparse hardening, quarantine integrity/race protections, allowlists and hash-cache hardening.

### v0.4.0 — Reputation + Network Intelligence
Local file prevalence/first-seen, Authenticode context, process→connection attribution and endpoint reputation.

### v0.4.1 — Behavioral Correlation Engine 2.0
Bounded temporal sequences, ancestry, evidence families, convergence scoring and explainable stages.

### v0.5.0 — Incident Correlation & Response Foundation
Consolidated incidents, bounded timelines, persistent response audit, PID-generation/path gates, guarded manual termination and encrypted quarantine.

### v0.6.0-beta.3 — Windows Protection Service + Authenticated IPC
**Windows native accepted/frozen by user acceptance on 2026-09-03.**

Frozen gates included:

- `211/211` development tests;
- frozen PyInstaller Protection Service;
- `BCSentinelProtection` real Windows service / `AUTO_START`;
- authenticated local Named Pipe IPC;
- remote-client rejection;
- kernel-derived client PID/token identity fallback;
- duplicate-engine guard;
- `protection-service-live = pass`;
- `health=HEALTHY`;
- 5,000-file Windows acceptance with `passed=true`, `critical_failures=[]`.

## v0.6.1 — Protection Service Hardening & Tamper Resistance

Status: **implemented in development; native Windows hardening freeze pending**.

Implemented:

- deploy frozen service under `%ProgramFiles%\BC Sentinel\Protection`;
- explicit Program Files and ProgramData ACL hardening;
- separate user-readable IPC token from machine-private integrity HMAC key;
- migration of valid v0.6.x config signatures;
- complete frozen-tree SHA-256 integrity manifest;
- post-deployment HMAC sealing of the manifest;
- sealed startup integrity gate;
- periodic self-protection monitor for install tree, config, ACL, SCM and audit chain;
- periodic forced full re-hash plus file identity metadata checks;
- unexpected executable/DLL/PYD/SYS/rule and reparse-point tamper detection;
- HMAC hash-chained privileged/lifecycle audit with truncation detection;
- SCM start/stop lifecycle audit;
- self-protection survives operator suspension of other protection engines;
- UI surfaces hardening degradation instead of claiming a fully healthy service;
- live hardening acceptance gate;
- reboot persistence acceptance tool;
- service idle/IPC/benign event-storm benchmark.

Development verification:

- `226/226` tests PASS;
- `compileall` PASS;
- synthetic 5,000-file scanner benchmark remains in the same development-class performance envelope as v0.6.

Native v0.6.1 freeze should require:

```powershell
.\.venv\Scripts\python.exe -m tools.windows_acceptance --benchmark-files 5000 --realtime-seconds 3 --service-live --output acceptance-v061-service-live.json
.\.venv\Scripts\python.exe -m tools.service_hardening_benchmark --idle-seconds 5 --ipc-requests 200 --storm-files 500 --output benchmark-v061-service.json
```

Then arm + verify the two-stage reboot acceptance.

Known user-mode boundaries:

- no PPL / kernel anti-tamper;
- administrator/kernel attackers remain outside the guarantee;
- no minifilter/WFP;
- no signed publisher trust chain for installer/update yet;
- no polished one-action UAC broker yet;
- no automatic destructive containment.

## v0.6.2 — Privileged Action Broker + Upgrade/Repair Hardening

Recommended next gate after v0.6.1 native freeze:

- tightly scoped one-action UAC broker so GUI remains standard-user;
- nonce/expiry/result-channel validation;
- clean service in-place upgrade/repair semantics;
- service binary version rollback policy;
- multi-user local client access policy;
- additional adversarial Named Pipe fuzzing/rate limits;
- stronger service-control ACL review.

## v0.7 — Signed Rules & Secure Update Channel

- signed/versioned YARA/behavioral/IOC packages;
- staged download;
- publisher/signature/hash verification;
- atomic activation;
- last-known-good rollback;
- secure app/service updater foundation.

## v0.8 — Ransomware Shield 2.0 / Recovery

- faster process attribution during file storms;
- service-owned high-confidence containment workflow;
- protected recovery journal;
- bounded version/copy-on-write strategy;
- integrity-checked rollback;
- disk-space/abuse limits.

## v0.9 — macOS Native Protection Foundation

A Mac installer comes only after a real native backend using supported Apple security APIs and signed/notarized helper lifecycle.

## v0.10 — Production Packaging

- signed Windows GUI/service binaries;
- installer upgrade/repair/uninstall;
- secure updater bootstrap;
- signed/notarized macOS package path.

## v1.0 — Production Endpoint Protection

Production only after protected service, secure updates, high-volume false-positive testing, rollback/runbooks and advertised platform capabilities are validated.

AI remains advisory/explanatory. Deterministic protection must work without a model or cloud dependency.
