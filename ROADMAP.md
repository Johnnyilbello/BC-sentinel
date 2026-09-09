# BC Sentinel — Product & Security Roadmap

Current development line: **v0.10.0-rc.1 — Web Protection Consolidation**.

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

### v0.10.0-beta.2 — Reversible Web Response / Blocking — **accepted development baseline**

- deterministic fail-closed response qualification separate from phishing heuristics;
- signed IOC only for automatic eligibility; local heuristics alone can never create an address block;
- same-PID DNS + observed network requirement for signed-domain containment;
- shared-IP/CDN guard rejects address containment;
- BC-owned temporary firewall containment with bounded TTL and explicit operator approval;
- idempotent repeated actions and same-address active-lease deduplication;
- manual rollback, TTL expiry, restart recovery and conservative stale-rule cleanup;
- no MITM, root CA, hosts-file mutation, global firewall-default change or origin-only file quarantine.

### v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation — **baseline accepted on Windows**
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

**Acceptance status:** accepted as a regression baseline through the later Beta2/Beta3 Windows validation. Its safety invariants remain frozen into RC1.

### v0.10.0-beta.2 — Reversible Web Response
- explicit, reversible DNS/network-layer containment only when signed qualification gates are satisfied;
- no heuristic-only address blocking;
- shared-IP/CDN safeguards and UAC approval retained;
- bounded TTL, audit, exact finding revalidation, deduplication, rollback and restart recovery.

### v0.10.0-beta.3 — Anti-Scam / Clone-Site Expansion — **current candidate**
- protected-brand claims on non-canonical domains;
- credential/payment form and cross-origin sensitive-form destination analysis;
- bounded scam/fraud patterns requiring independent structural risk;
- remote-support, investment/crypto and delivery/payment multi-signal detection;
- heuristic cap remains 49 and page context cannot auto-block;
- both master test launchers now include upgrade/repair and true standard-user -> UAC; reboot alone remains deferred until final roadmap closure.

### v0.10.0-rc.1 — Consolidation — **current**
- Beta1→Beta3 regression freeze;
- high-volume benign-site/enterprise compatibility matrix;
- performance/latency checks;
- native Windows/live evidence for advertised v0.10 behavior;
- master NORMAL and ADMIN launchers always include upgrade, repair and true standard-user -> UAC;
- reboot remains the only intentionally deferred gate until final roadmap acceptance.

Beta3 Windows baseline entering RC1 (2026-09-08): 545/545 full regression, 115/115 admin/security, build, anti-downgrade, real repair, Beta1/Beta2/Beta3 service-live, Windows native acceptance, hardening benchmark and standard-user -> UAC all PASS.

RC1 local pre-delivery: 547 passed + 2 Windows-native skips, 323-case benign compatibility matrix with zero failures, compileall and RC1 local acceptance PASS.

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

## Historical accepted response details retained

#### Threat Decision Center — end-to-end service boundary
Qualified HIGH/CRITICAL detections present the explicit decision card requested by the product design:
- **Quarantena · consigliato** — preferred reversible action;
- **Elimina definitivamente** — destructive action only after explicit confirmation and immediate path/snapshot/SHA-256 revalidation;
- **Mantieni questa volta** — handles only the current occurrence and never creates persistent trust;
- **Consenti hash** — trusts only the exact SHA-256; a changed file is analyzed again;
- when the Protection Service owns protection, quarantine and permanent deletion now execute through the privileged service/UAC boundary rather than directly in the standard-user GUI;
- the service receives the expected detection SHA-256 and refuses quarantine/delete when the file identity changed after detection;
- the privileged threat-file endpoint is restricted to qualified HIGH/CRITICAL detections with score >=70 and cannot act as a generic privileged file remover;
- BC Sentinel-managed paths and the protected Windows system tree fail closed for quarantine/permanent-delete response actions;
- local fallback keeps the same identity-safe checks when the service is unavailable;
- every completed user decision is recorded with action, status, path, SHA-256, score, level and `explicit_user_decision=true`;
- permanent destruction remains manual-only; no detection engine may silently delete a file in v0.7.1;
- publisher-wide trust remains a separate future high-friction action and may only be offered after locally verified `Authenticode=Valid`.

#### Harmless Threat Decision acceptance
`tools.threat_decision_acceptance` uses only temporary harmless fixtures and proves:
1. deterministic simulated EICAR-class detection reaches CRITICAL;
2. quarantine accepts only the exact expected SHA-256;
3. encrypted quarantine restore reproduces the exact fixture;
4. permanent delete revalidates the detected identity before unlink;
5. `Mantieni questa volta` leaves the allowlist unchanged;
6. `Consenti hash` trusts the original digest but not changed bytes.

### v0.7.1-beta.1 — Firewall Drift Detection & Reconciliation (native Windows accepted)
- persistent desired state for every BC Sentinel-managed firewall rule;
- semantic drift detection for missing, disabled and modified owned rules;
- `untracked_owned` and exact managed-group collision observation;
- periodic service-side drift inspection integrated into the hardening cycle;
- standard-user read-only drift posture;
- privileged, explicitly approved reconciliation of desired BLOCK rules only;
- no reconciliation of collisions, untracked rules, third-party rules or global Windows Firewall policy;
- native Windows acceptance proved external disable detection, exact owned-rule restoration, cleanup and baseline restoration.

#### Response Policy Engine — later v0.7.x
Planned policy tiers remain explainable and reversible: LOW → log/notify; SUSPICIOUS → review; HIGH → ask user; CRITICAL → policy may quarantine automatically only after dedicated acceptance. Permanent destruction remains manual-only unless a future release earns a separate safety gate.
