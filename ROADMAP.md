# BC Sentinel — Product & Security Roadmap

Current development line: **v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation**.

2026-09-08 source-of-record baseline: v0.9.0-rc.1 checkpoint 4 completed **578 tests, zero skipped**, fresh service/broker builds, artifact integrity, local RC acceptance and the native Authenticode sub-gate. The elevated current-build/live/UAC/upgrade/repair/reboot gates remain **DEFERRED / OPEN**. Development is advancing to v0.10 by explicit decision, but v0.9 is **not** retroactively frozen or production accepted.

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
Program Files deployment, split IPC/integrity secrets, authenticated full-tree manifest, ACL/SCM/config/audit posture, timestamp-restoration tamper detection and reboot persistence.

### v0.6.2 — Privileged Action Broker + Transactional Upgrade/Repair
Standard-user GUI → one-action UAC broker → Protection Service, server-side single-use tickets, SID/session/PID binding, replay rejection, protected broker binary, authenticated upgrade baseline, anti-downgrade, same-version repair, staged deployment, rollback journal and integrity re-sealing.

## v0.7 — Firewall & Network Threat Prevention

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

### v0.7.2-beta.4 — Browser Download Protection & Web Incident Chain — accepted through v0.8 regression
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

### v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation
PowerShell/script/LOLBin command context, parent/child and bounded process→network correlation, credential-stealer indicators and conservative false-positive gates. One dual-use tool/evidence family remains below HIGH; no automatic kill/delete/quarantine.

### v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening — **native freeze deferred**
Checkpoint 4 on 8 September 2026 is the current baseline:
- **578 tests passed, zero skipped**;
- fresh service/broker builds passed;
- artifact integrity and local RC acceptance passed;
- Authenticode filename command injection corrected;
- OS executable/module selection pinned;
- native Authenticode sub-gate passed;
- earlier updater/quarantine/YARA regressions remain covered.

Still OPEN/DEFERRED: elevated current-build foundation, live Protection Service, UAC, upgrade/repair, reboot persistence and aggregate native benchmarking. These are technical debt, not PASS evidence.

## v0.10 — Web Protection, Anti-Phishing & Anti-Truffa — Mature Expansion

### v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation — **current**
Goal: mature the existing v0.7.2 web stack without weakening its safety boundaries.

Implementation delta:
- local/offline URL and domain reputation assessment;
- IDN/Punycode and mixed-script detection retained and made more explainable;
- bounded protected-identity look-alike detection;
- edit-distance-one typosquatting evidence;
- brand-token-on-noncanonical-host evidence;
- explicit separation of declared identity, observed host and canonical identity;
- userinfo/raw-IP/deep-subdomain/hostname-obfuscation evidence;
- bounded redirect-chain context including canonical-brand → look-alike and raw-IP transitions;
- conservative scam/fraud lure families that score only with independent structural risk;
- stable `WDR-*` heuristic fingerprint to support deterministic deduplication beneath existing persistent `BCW-*` findings;
- signed IOC and exact-domain trust precedence preserved;
- browser/process → DNS/domain → network → download → execution → incident remains the existing authoritative correlation chain;
- download origin never overrides the independent file verdict.

Mandatory Beta1 safety invariants:
- heuristic-only score ≤49;
- no heuristic-only HIGH/CRITICAL qualification;
- no heuristic auto-block;
- no heuristic-only quarantine/delete/process kill/persistence mutation;
- no HTTPS MITM, root CA, TLS proxy or traffic decryption;
- no mandatory cloud/external runtime dependency;
- exact-domain trust cannot override active signed IOC;
- shared-IP/CDN guard remains unchanged;
- all high-impact response stays behind the existing protected/UAC-backed workflows.

Beta1 deterministic test matrix must cover:
- benign brand-similar domains;
- benign and suspicious IDN/Punycode;
- mixed-script look-alikes;
- typosquatting;
- deep/subdomain brand abuse;
- URL userinfo;
- raw-IP URLs;
- redirect chains;
- signed malicious IOC;
- exact-domain trust;
- signed IOC overriding older trust;
- enterprise false-positive fixtures for Microsoft, Google, GitHub, common CDN, Cloudflare, Salesforce and Atlassian;
- existing browser/non-browser context and browser→download→execution regressions from v0.7.2-beta.3/beta.4.

Acceptance gates:
- `web-reputation-v010-beta1-foundation`;
- `web-reputation-v010-beta1-live`.

**Current acceptance status:** NOT ACCEPTED. The connected GitHub repository contains the security delta, while the complete checkpoint-4 source tree is not present. The older v0.10 ZIP predates checkpoint 4 and must not be used to overwrite later hardening. Apply/rebase this delta onto the checkpoint-4 full tree, then run targeted tests + the complete regression suite (floor 578 existing tests, plus new v0.10 tests), compileall, local acceptance, fresh builds and artifact integrity. Native v0.9 debt remains deferred/open rather than falsified as PASS.

### Planned v0.10.0-beta.2 — Reversible Web Response
- explicit, reversible DNS/network-layer containment only when existing qualification gates are satisfied;
- no heuristic-only address blocking;
- preserve shared-IP/CDN safeguards and UAC approval;
- bounded TTL, audit and exact finding revalidation.

### Planned v0.10.0-beta.3 — Anti-Scam / Clone-Site Expansion
- richer impersonation evidence from locally available context;
- bounded fraud/scam patterns;
- stronger redirect and download-risk correlation;
- false-positive stress matrix before RC.

### Planned v0.10.0-rc.1 — Consolidation
- Beta1→Beta3 regression freeze;
- high-volume benign-site/enterprise compatibility matrix;
- performance/latency checks;
- native Windows/live evidence for advertised v0.10 behavior.

## v0.11 — EDR Core
- durable endpoint activity timeline;
- process/file/network/persistence identity graph;
- IOC hunting and retrospective search;
- root-cause and process-tree incident views;
- reversible host/network containment;
- explainable automated response policies;
- enterprise policy/audit foundation.

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