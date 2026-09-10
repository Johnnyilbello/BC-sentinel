# BC Sentinel — Product & Security Roadmap

Current development line: **v0.11.0-beta.2 — EDR Service Integration, Retrospective Hunting & Root Cause**.

2026-09-10 source-of-record: `v0.11.0-beta.1` EDR Core Foundation has passed its complete one-command Windows gate with 609 pytest tests green, native/admin regression coverage, upgrade/repair, enforced service-performance thresholds and standard-user -> UAC flow. Reboot persistence remains intentionally deferred to final-roadmap validation rather than being silently marked PASS.

BC Sentinel is evolving from an antivirus MVP into an integrated endpoint-security suite. Antivirus, firewall, anti-phishing, EDR, sandbox, IDS/IPS, privacy, identity controls and Rescue & Recovery feed the same explainable event/correlation/incident model. AI remains advisory/explanatory: deterministic protection and recovery must work without a model or mandatory cloud dependency.

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

### v0.11.0-beta.1 — EDR Core Foundation — accepted baseline
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

### v0.11.0-beta.2 — Service Integration, Retrospective Hunt & Root Cause — **current**
- indexed IOC hunting over durable telemetry;
- process ancestry/descendant root-cause views;
- time-window and indicator search;
- incident-to-telemetry evidence navigation;
- bounded retention/compaction tests and false-positive stress matrices;
- Protection Service ownership of the EDR telemetry lifecycle;
- continuous native process/file/network/DNS/download/persistence ingestion;
- authenticated Named Pipe query endpoints for timeline, process tree, incidents and hunts;
- Security Center Inbox integration for qualified EDR incidents;
- no autonomous destructive response.

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

## BC Sentinel Rescue & Recovery — cross-product recovery track

Goal: recover severely infected Windows PCs even when the installed operating system is too slow, unstable or compromised to install or normally execute BC Sentinel. The objective is to make formatting/reimaging the **last resort**, never to claim recovery when system integrity cannot be demonstrated.

This track may reuse accepted Antivirus, Antimalware, Threat Intelligence, EDR and integrity primitives, but must remain operationally separable from the installed product. Every milestone requires automatic tests, compromised-PC scenarios, measurable acceptance criteria and preservation of all existing protection invariants.

### RR-0 — Rescue Architecture & Recovery Safety Model
**Codex reasoning: Extra High.**
- define trust boundaries for running from compromised Windows versus independent boot media;
- define read-only-first acquisition, evidence preservation and rollback model;
- define supported Windows/UEFI/Secure Boot/storage/encryption scenarios without bypassing platform security controls;
- define signed rescue artifacts, update provenance and offline threat-package trust chain;
- define a recovery-state model: `recoverable`, `recovered_with_warnings`, `integrity_unproven`, `reimage_required`;
- define resource budgets and benchmark methodology before implementation.

Acceptance: architecture/threat-model review complete; destructive operations impossible without an explicit repair plan; every repair action has precondition, evidence, audit and rollback/backup strategy; unsupported encrypted/locked volumes fail closed.

### RR-1 — BC Sentinel Portable
**Codex reasoning: High for implementation; Extra High for security boundary changes.**
- portable launcher from USB/removable storage with no MSI/service installation requirement;
- minimal-resources mode focused on triage, scan, threat intelligence and evidence collection;
- optional elevation only for capabilities that genuinely require it;
- no dependency on the health of the installed BC Sentinel service;
- signed/offline threat package support and local report export.

Acceptance: launches from removable media on supported Windows without installation; leaves no persistent service/startup entry after exit; idle CPU target <=5% of one core and working-set target <=250 MB in minimal mode on the reference test machine; scan results match the same deterministic engine/rules used by the installed product for the same fixture set.

### RR-2 — BC Sentinel Rescue USB
**Codex reasoning: Extra High for architecture/security; High for ordinary implementation.**
- bootable recovery environment independent from the installed Windows instance;
- signed and integrity-verified rescue image/build pipeline;
- safe storage discovery and explicit system-volume selection;
- read-only mount by default; write access only when entering an explicit repair workflow;
- offline threat intelligence update import from trusted removable/network source when available.

Acceptance: boots independently on the defined UEFI/Secure Boot compatibility matrix; can identify supported Windows installations without executing code from them; verifies its own image/rules before scan; refuses repair if rescue-image integrity is invalid or target-volume state is ambiguous.

### RR-3 — Offline Threat Scanner
**Codex reasoning: Extra High for parser/security architecture; High for implementation.**
- scan files and alternate persistence-relevant locations without executing target binaries;
- inspect offline registry hives, services, drivers, startup entries, scheduled tasks and persistence points;
- inspect browser configuration/artifacts and offline network/proxy/DNS/firewall configuration where safely parseable;
- inspect boot configuration and boot-critical drivers/components;
- correlate findings with signed IOC/YARA/file verdicts and the existing explainable incident model;
- read-only by default and bounded against malformed/corrupt offline data.

Acceptance: deterministic synthetic compromised images cover each advertised persistence family; malformed hives/configuration cannot crash the scanner or trigger writes; benign Windows compatibility matrix remains within the defined false-positive budget; every HIGH/CRITICAL offline finding contains reproducible evidence.

### RR-4 — Repair Engine
**Codex reasoning: Extra High for architecture/security and any boot/registry/system repair primitive; High for ordinary implementation.**
- generate an explicit repair plan before any mutation;
- remove/disable qualified malicious persistence while preserving unrelated configuration;
- restore selected Windows security/network/service/startup configuration altered by malware;
- support system-component verification/repair using trusted local or Microsoft-supported sources where available;
- repair boot configuration only through narrowly scoped, validated operations;
- transaction journal, backup, audit and rollback for every reversible action;
- never use broad destructive cleanup merely to make a test pass.

Acceptance: every supported repair has before/after evidence and rollback/backup; power-loss/interrupted-repair simulations recover to a known state; unrelated services/tasks/registry values remain unchanged in compatibility fixtures; ambiguous/high-risk repairs require operator confirmation or remain report-only.

### RR-5 — Safe Data Rescue
**Codex reasoning: Extra High for trust/integrity model; High for implementation.**
- copy user-selected data before invasive recovery operations;
- source volume treated read-only whenever possible;
- exclude or quarantine known malicious executables/scripts according to an explicit policy rather than silently copying them into clean systems;
- preserve metadata where safe and calculate hashes/manifests for copied data;
- resumable copy with error accounting and destination-capacity checks;
- clear separation between rescued user data and executable/system artifacts.

Acceptance: byte/hash verification for successfully copied files; interrupted copies resume without silently corrupting prior output; malicious fixture files are flagged according to policy; source data is never deleted or modified by Data Rescue; final manifest lists copied, skipped, suspicious and unreadable items.

### RR-6 — Integrity Verification & Recovery Certification
**Codex reasoning: Extra High.**
- rescan after repair using independent/offline evidence where possible;
- verify Windows system/security configuration, services, drivers, startup, scheduled tasks, persistence, browser/network configuration and boot state;
- verify repaired files/components against trusted hashes/signatures/sources where available;
- compare pre-repair and post-repair state and explain every residual warning;
- produce a signed/tamper-evident final report with recovery decision.

Acceptance: the system may be marked `recoverable/recovered` only when all mandatory integrity checks pass; unresolved boot/system-component ambiguity must produce `integrity_unproven` or `reimage_required`; no “clean” verdict from scan results alone; final report contains evidence, actions, rollback records, unresolved findings and recommended next step.

### Rescue & Recovery integrated validation
Before this macro-area can be advertised as production recovery capability:
- validate representative lightly, moderately and severely compromised Windows images/VMs;
- include broken/disabled antivirus, high CPU/low-memory, damaged startup/services, offline persistence, malicious driver/boot fixtures and corrupt configuration scenarios;
- prove Portable and Rescue USB operate independently of a broken installed service;
- prove Safe Data Rescue before invasive operations;
- prove repair does not weaken existing BC Sentinel safeguards;
- run cross-version regression, fuzz/malformed-input tests, resource benchmarks and interrupted-repair/restart scenarios;
- keep reimage/formatting as an explicit last-resort outcome when trustworthy recovery cannot be established.

### Codex execution policy for Rescue & Recovery
- **Reasoning: Extra High** for architecture, threat modeling, trust boundaries, boot/offline parsing, repair primitives, integrity certification and security reviews.
- **Reasoning: High** for ordinary implementation, tests, tooling and incremental integration once the security design is frozen.
- Implement one milestone/checkpoint at a time; do not advance when acceptance criteria are red.
- Do not weaken existing antivirus, EDR, firewall, web, update, UAC, integrity or performance gates to make Rescue tests pass.

## Later platform/product milestones

### macOS Native Protection Foundation
Only after a real native backend using supported Apple security APIs and signed/notarized helper lifecycle.

### Production Packaging
Signed Windows GUI/service/broker binaries, installer upgrade/repair/uninstall, secure updater bootstrap, release provenance and reproducible release checks.

### v1.0 — Production Endpoint Protection Suite
Production only after protected service, secure updates, false-positive/compatibility testing, rollback/runbooks and every advertised capability has native acceptance evidence.
