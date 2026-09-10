# BC Sentinel — Product & Security Roadmap

Current development line: **v0.11.0-beta.1 — EDR Core Foundation**.

2026-09-08 source-of-record: v0.10.0-rc.1 Web Protection consolidation has passed its normal-orchestrated regression path, including full suite, v0.10 Beta1/Beta2/Beta3/RC1 compatibility, native/admin phase, upgrade, repair and standard-user -> UAC. Reboot persistence remains intentionally deferred to the final roadmap validation rather than being silently marked PASS.

BC Sentinel is evolving from an antivirus MVP into an integrated endpoint-security suite. Antivirus, firewall, anti-phishing, EDR, sandbox, IDS/IPS, privacy and identity controls feed the same explainable event/correlation/incident pipeline. AI remains advisory/explanatory: deterministic protection must work without a model or mandatory cloud dependency.

## Frozen / accepted foundation

### v0.3.1 — Security Hardening
PID-reuse-safe identity, stronger ETW attribution, path/reparse hardening, quarantine integrity/race protections, allowlists and hash-cache hardening.

### v0.4.x — Reputation, Network Intelligence & Behavioral Correlation
Local file prevalence, Authenticode context, process→connection attribution, endpoint reputation and bounded multi-signal behavioral correlation.

### v0.5.0 — Incident Correlation & Response Foundation
Consolidated incidents, bounded timelines, persistent response audit, PID-generation/path gates, guarded manual termination and encrypted quarantine.

### v0.6.0 — Windows Protection Service
Windows service, authenticated local Named Pipe IPC, remote-client rejection, kernel-derived client identity, duplicate-engine guard and service-owned protection runtime.

### v0.6.1 — Service Hardening & Tamper Resistance
Program Files deployment, split IPC/integrity secrets, authenticated full-tree manifest, ACL/SCM/config/audit posture, timestamp-restoration tamper detection and reboot persistence architecture.

### v0.6.2 — Privileged Action Broker + Transactional Upgrade/Repair
Standard-user GUI → one-action UAC broker → Protection Service, server-side single-use tickets, SID/session/PID binding, replay rejection, protected broker binary, authenticated upgrade baseline, anti-downgrade, same-version repair, staged deployment, rollback journal and integrity re-sealing.

## v0.7 — Firewall & Network Threat Prevention

### v0.7.1 — Threat Decision Center & Managed Firewall Foundation
- **Threat Decision Center** for explicit HIGH/CRITICAL decisions and persistent operator acknowledgement;
- BC-owned firewall policy only;
- drift detection and reconciliation without mutating unrelated third-party rules;
- conflict/advisory engine for overlapping external ALLOW rules;
- signed IOC qualification for temporary reversible containment;
- Security Center Inbox remains the durable decision surface.

### v0.7.2-beta.1 — Web Protection / Anti-Phishing Foundation — accepted baseline
- PID-scoped Windows DNS Client ETW correlation;
- DNS→IP→connection attribution remains short-lived and PID-scoped;
- signed domain IOC can produce deterministic HIGH/CRITICAL outcomes;
- structural IDN/Punycode, deep-subdomain, raw-IP and userinfo heuristics;
- heuristic-only score capped below HIGH;
- no HTTPS MITM/root CA/TLS proxy/decryption;
- Web Protection remains observe/recommend rather than autonomous filtering.

### v0.7.2-beta.2 — Active Web Protection & DNS Threat Response — accepted baseline
- persistent `BCW-*` actionable findings;
- same-PID DNS + observed connection requirements for domain-derived containment;
- conservative shared-IP/CDN guard;
- UAC-backed BC-owned temporary outbound BLOCK leases;
- no heuristic auto-block and no third-party/global firewall mutation.

### v0.7.2-beta.3 — Domain Trust, Provenance & Browser Context — accepted baseline
- exact-domain trust only, no wildcard trust;
- precedence: active signed IOC > exact-domain trust > local heuristics;
- trust is audited/revocable and cannot suppress a newer signed IOC;
- local bounded domain-reputation aggregates;
- exact known browser executables add browser-family context;
- provenance is exposed in Web assessments.

### v0.7.2-beta.4 — Browser Download Protection & Web Incident Chain — accepted baseline
- same-PID exact-browser domain/network → file download provenance;
- persistent `BCD-*` download records with independent origin and file verdicts;
- realtime scanner verdict linkage without origin-driven auto-quarantine;
- downloaded-file execution evidence feeds the incident pipeline;
- no MITM HTTPS or browser extension.

## v0.8 — Signed Threat Intelligence & Secure Update Channel

### v0.8.0-rc.1 — accepted baseline
Signed threat packages, content-key lifecycle/revocation, signed remote index, pinned controlled retrieval, activation recovery/rollback and release hardening are frozen regression requirements. Remote content remains no-auto-stage/no-auto-activate and deterministic protection remains available offline.

## v0.9 — Antispyware & Advanced Antimalware

### v0.9.0-beta.1 — accepted feature baseline
Read-only persistence/browser/network configuration inventory, stable `BCP-*` findings, Authenticode/context enrichment and conservative multi-signal correlation without automatic destructive remediation.

### v0.9.0-beta.2 — accepted feature baseline
HMAC-authenticated reversible remediation plans for selected Run/RunOnce, Startup, Scheduled Task, service and browser-policy states; apply/restore remain privileged and identity/race checked. WMI/DNS/proxy stay review-only.

### v0.9.0-beta.3 — accepted feature baseline
PowerShell/script/LOLBin command context, parent/child and bounded process→network correlation, credential-stealer indicators and conservative false-positive gates. One dual-use tool/evidence family remains below HIGH; no automatic kill/delete/quarantine.

### v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening — historical baseline
The v0.9 RC1 local/security foundation remains a mandatory regression layer. Later v0.10 Windows validation closed multiple cross-version service/UAC/update paths, but no historical test may infer a production freeze solely from a newer APP_VERSION.

## v0.10 — Web Protection, Anti-Phishing & Anti-Truffa — consolidated baseline

### v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation — accepted baseline
- local/offline URL and domain reputation assessment;
- IDN/Punycode and mixed-script detection;
- bounded protected-identity look-alike detection;
- edit-distance-one typosquatting evidence;
- brand-token-on-noncanonical-host evidence;
- explicit separation of declared identity, observed host and canonical identity;
- userinfo/raw-IP/deep-subdomain/hostname-obfuscation evidence;
- bounded redirect-chain context;
- conservative scam/fraud lure families requiring independent structural risk;
- stable `WDR-*` heuristic fingerprint;
- signed IOC and exact-domain trust precedence preserved.

Mandatory safety invariants retained beyond v0.10:
- heuristic-only score ≤49;
- no heuristic-only HIGH/CRITICAL qualification;
- no heuristic auto-block;
- no heuristic-only quarantine/delete/process kill/persistence mutation;
- no HTTPS MITM, root CA, TLS proxy or traffic decryption;
- no mandatory cloud/external runtime dependency;
- exact-domain trust cannot override active signed IOC;
- shared-IP/CDN guard remains fail-closed;
- high-impact response stays behind protected/UAC-backed workflows.

Acceptance gates retained:
- `web-reputation-v010-beta1-foundation`;
- `web-reputation-v010-beta1-live`.

### v0.10.0-beta.2 — Reversible Web Response — accepted baseline
- explicit, reversible network-layer containment only after deterministic qualification;
- same-PID DNS/network revalidation;
- no heuristic-only address blocking;
- shared-IP/CDN safeguards;
- bounded TTL, deduplication, audit, restart recovery and stale-rule cleanup.

### v0.10.0-beta.3 — Clone Site & Scam/Fraud Detection Expansion — accepted baseline
- protected-brand impersonation evidence;
- noncanonical credential-form detection;
- cross-origin sensitive-form destination analysis;
- bounded support/investment/payment scam families;
- multi-signal structural requirement;
- no page-context auto-block and no heuristic destructive response.

### v0.10.0-rc.1 — Web Protection Consolidation — accepted development baseline
- Beta1→Beta3 regression freeze;
- 300+ benign-site/enterprise compatibility matrix;
- local page-assessment performance thresholds;
- normal-user master launcher automatically requests UAC for the privileged phase;
- native/admin, service-live, upgrade, repair and standard-user→UAC paths covered by the orchestrated validation;
- reboot persistence deliberately deferred to the final roadmap gate.

Historical profile IDs remain frozen even on v0.11+:
- deception: `v0.10.0-beta.1`;
- reversible response: `v0.10.0-beta.2`;
- clone/scam: `v0.10.0-beta.3`;
- consolidation: `v0.10.0-rc.1`.

## v0.11 — EDR Core

### v0.11.0-beta.1 — EDR Core Foundation — **current**
Goal: add a durable endpoint telemetry and incident-correlation layer without weakening the deterministic safety boundaries already accepted in v0.10.

Implemented Beta1 foundation:
- durable local endpoint telemetry store;
- process/file/network/persistence event ingestion;
- PID/PPID process-tree reconstruction;
- same-chain download → execution → network → persistence correlation;
- stable event deduplication;
- per-PID/window flood guard;
- queryable retrospective event history;
- persistent explainable EDR incidents;
- bounded local performance acceptance;
- EDR profile surfaced independently from the frozen v0.10 web profiles.

Mandatory Beta1 safety invariants:
- no single heuristic may independently qualify HIGH;
- no automatic process kill;
- no automatic file delete;
- no automatic host isolation;
- no mandatory cloud dependency;
- v0.10 anti-phishing/shared-IP/containment invariants remain unchanged;
- legacy regression gates must accept newer product versions while continuing to verify their historical frozen profile IDs and security behavior.

Beta1 acceptance:
- full pytest regression suite;
- `tools.v011_edr_acceptance`;
- v0.10 Beta1/Beta2/Beta3/RC1 local regressions;
- compileall;
- fresh Protection Service and UAC Broker build;
- native/admin targeted regression;
- transactional upgrade/repair;
- service-live v0.10 regressions;
- Windows acceptance and hardening benchmark;
- standard-user → one-action UAC broker acceptance;
- reboot persistence deferred to final roadmap validation.

### Planned v0.11.0-beta.2 — Retrospective Hunt & Root Cause
- indexed IOC hunting over durable telemetry;
- process ancestry/descendant root-cause views;
- time-window and indicator search;
- incident-to-telemetry evidence navigation;
- bounded retention/compaction tests and false-positive stress matrices.

### Planned v0.11.0-beta.3 — Reversible EDR Response Foundation
- explicitly approved reversible endpoint/network response only;
- exact incident/entity revalidation before action;
- rollback/TTL/audit/restart recovery;
- no autonomous destructive remediation.

### Planned v0.11.0-rc.1 — EDR Consolidation
- Beta1→Beta3 regression freeze;
- high-volume telemetry and compatibility tests;
- service/native evidence for advertised EDR behavior;
- final cross-version lifecycle review before v0.12.

## v0.12 — Sandbox & Dynamic Analysis
- isolated suspicious-file execution;
- pre/post filesystem, registry, process and network diff;
- behavioral scoring;
- detonation evidence ingestion into incident correlation;
- strict resource/time/network controls;
- no execution of unknown samples on the host OS.

## v0.13 — IDS/IPS & Brute-Force Protection
- Windows Filtering Platform flow/packet research;
- signature + behavioral intrusion detection;
- explicit prevention safety gates;
- brute-force/password-spray/credential-stuffing detection;
- adaptive throttling/rate limiting;
- IP/ASN/account/device/network correlation;
- RDP/remote-service protection.

## v0.14 — Privacy Protection & Safe Banking
- webcam/microphone monitoring and alerts;
- per-application policy where supported;
- privacy-access correlation with EDR;
- protected-session/Safe Banking design;
- browser/process interference detection;
- keylogger/injection protections where safely supportable.

## v0.15 — Identity Protection, Password Manager & 2FA
- encrypted local vault;
- password health/reuse checks;
- privacy-preserving breach-monitoring integration;
- TOTP/2FA;
- clipboard/credential-access hardening;
- identity-risk events feeding incident correlation.

## v0.16 — VPN & Untrusted-Network Protection
- integrated or tightly controlled companion VPN;
- kill switch and secure DNS;
- untrusted Wi-Fi protection;
- per-application routing/policy where supported;
- VPN state integrated with firewall and incident engine.

## Later platform/product milestones

### macOS Native Protection Foundation
Only after a real native backend using supported Apple security APIs and signed/notarized helper lifecycle.

### Production Packaging
Signed Windows GUI/service/broker binaries, installer upgrade/repair/uninstall, secure updater bootstrap, release provenance and reproducible release checks.

### v1.0 — Production Endpoint Protection Suite
Production only after protected service, secure updates, false-positive/compatibility testing, rollback/runbooks and every advertised capability has native acceptance evidence.
