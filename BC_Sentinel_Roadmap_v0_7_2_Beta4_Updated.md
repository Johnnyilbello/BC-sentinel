# BC Sentinel — Product & Security Roadmap

Current development line: **v0.7.2 Beta — Domain Trust, Provenance & Browser Context**.

BC Sentinel is evolving from an antivirus MVP into an integrated endpoint-security suite. The architectural rule is that antivirus, firewall, anti-phishing, EDR, sandbox, IDS/IPS, privacy and identity controls feed the same explainable event/correlation/incident pipeline. AI remains advisory/explanatory: deterministic protection must work without a model or cloud dependency.

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
Accepted Windows path includes standard-user GUI → one-action UAC broker → Protection Service, server-side single-use tickets, requester SID/session/PID binding, replay rejection, protected broker binary, authenticated upgrade baseline, anti-downgrade, same-version repair, staged deployment, rollback journal and integrity re-sealing.

## v0.7 — Firewall & Network Threat Prevention

### v0.7.2-beta.3 — Domain Trust, Provenance & Browser Context (current)
- persistent domain trust is exact-domain only, wildcard-free, bounded to 512 entries and modified only through the authenticated Protection Service/UAC boundary;
- precedence is fail-safe: active signed IOC > local exact-domain trust > local heuristics; signed IOC state can visibly override but never be suppressed by older local trust;
- trust changes are audited, revocable, and resolve only pending findings for the exact domain;
- Web assessments expose structured provenance for signed IOC, local trust and heuristic evidence;
- bounded local domain-reputation aggregates track first/last seen, observation counts, maximum score and small process/address samples without claiming cloud-wide reputation;
- exact known browser executables add browser-family context to network findings while signer text remains evidence rather than browser identity;
- Security Center adds domain details, `Consenti dominio`, `Revoca fiducia` and explicit `IOC override fiducia`;
- Beta 2 containment prerequisites remain unchanged: same-PID DNS + actual same-PID connection + non-shared address + signed evidence + explicit UAC approval;
- no HTTPS MITM, root CA, wildcard trust, heuristic auto-block or third-party/global firewall mutation.

### v0.7.2-beta.2 — Active Web Protection & DNS Threat Response (native Windows accepted)
- persistent `BCW-*` Web Protection findings separate actionable state from raw ETW history;
- process connections are enriched with current PID-scoped DNS context and signed IOC web decisions;
- conservative shared-IP/CDN detection suppresses address containment for domain-only IOC evidence;
- signed network IOC evidence remains address-qualified because the signed indicator targets the network itself;
- `web_containment_create` accepts only a persisted eligible finding and rechecks signed IOC, DNS mapping, PID and shared-IP posture at action time;
- DNS-only IOC evidence cannot block an address; domain-derived containment additionally requires an observed same-PID network connection;
- Web Protection containment uses the one-action UAC broker, BC-owned outbound BLOCK rules and a bounded 60–3600 second lease;
- ignore/review decisions are authenticated but non-privileged and never create durable trust;
- Security Center exposes `Ignora una volta` and `Blocca 15 min`, disabling block on shared infrastructure;
- Windows acceptance adds 3-run median scanner benchmarking to distinguish stable regressions from single-run host I/O variance;
- no HTTPS MITM, root CA, heuristic auto-block or third-party/global firewall mutation.

### v0.7.2-beta.1 — Web Protection & Anti-Phishing Foundation (native Windows accepted)
- Windows DNS Client ETW telemetry is correlated with process/network events; DNS provider failure does not disable existing process/file ETW telemetry;
- DNS→IP→connection correlation is strictly PID-scoped and short-lived; BC Sentinel does not globally infer a domain from an IP because CDNs/shared hosting make that unsafe;
- signed `domain` IOC evidence can produce deterministic HIGH/CRITICAL malicious verdicts and a `containment_recommended` decision;
- structural URL/domain anti-phishing heuristics cover IDN/Punycode, deep subdomains, unusual hostname structure, raw-IP URLs and URL userinfo;
- heuristic-only findings are hard-capped below score 50 and therefore cannot trigger HIGH/CRITICAL automatic response;
- Web Protection remains `observe_recommend`: it never creates firewall rules itself;
- no HTTPS MITM, root-certificate installation, local TLS proxy or traffic decryption;
- Protection Service exposes read-only `web_status`, `web_findings` and `web_assess`;
- Security Center adds Web Protection findings/manual URL analysis and Protection exposes DNS/Web posture;
- native acceptance requires PID-scoped DNS ETW active while preserving `mitm_https=false` and `auto_block=false`.

### v0.7.1-beta.3 — Signed IOC, Reversible Containment & Security Center Inbox (native Windows accepted)
- Ed25519-signed local IOC bundles with a pinned public trust anchor; the private signing key is never shipped with the product;
- canonical JSON signature verification, bounded feed size, validity-window checks, duplicate-indicator rejection and sequence-based anti-rollback;
- signed IOC kinds: SHA-256, bounded IPv4/IPv6 network indicators and domains;
- active signed SHA-256 IOC evidence takes precedence over an older local hash allowlist so a newly published known-bad identity requires a fresh explicit decision;
- signed network IOC evidence is integrated into local Network Intelligence with deterministic malicious status and explainable source;
- temporary containment leases are BC-owned outbound BLOCK rules only, with explicit privileged approval and TTL from 60 seconds to 24 hours;
- lease creation requires either an active signed IOC match or an existing incident score >=70; arbitrary privileged remote blocking is not exposed as a containment lease;
- expired leases are removed automatically because expiry is part of the explicitly approved lease; operator release is also supported and audited;
- lease release never edits third-party rules and removes stale BC desired state only for the exact ended lease;
- Security Center Inbox persists qualified HIGH/CRITICAL detections until an explicit decision is recorded; closing a popup no longer loses the pending decision;
- Inbox review revalidates the exact SHA-256 before acting and marks replaced/missing files without applying the old decision to new content;
- signed IOC feed import is exposed in Settings through the Protection Service/UAC boundary; the GUI cannot bypass signature verification;
- scanner phase profiling now measures hash identity, content read, YARA, PE, reputation and total cost; small fully-read files reuse the same in-memory bytes for YARA rather than reopening the file;
- Windows Firewall COM rule enumeration is materialized inside the COM apartment and released before apartment teardown; native beta.3 drift acceptance must confirm the remaining `IUnknown` warning is gone before this debt is closed;
- Windows acceptance adds critical side-effect-free gates for signed-feed verification/tamper rejection, containment qualification/release and persistent Inbox behavior.

### v0.7.1-beta.2 — Firewall Abuse Resistance, Policy Conflicts & Threat Decision E2E (native Windows accepted)
- bounded sliding-window rate limiting for privileged firewall mutations, response actions and one-action UAC preparation;
- authenticated IPC malformed-message flood protection with explicit `rate_limited` responses and cooldown metadata;
- service status exposes abuse-protection metrics without leaking secrets or ticket identifiers;
- read-only firewall Policy Conflict Engine separates blocking managed-group collisions from non-blocking external ALLOW overlaps;
- external ALLOW overlap findings are advisory only because Windows BLOCK precedence remains authoritative; BC Sentinel never edits the external rule;
- duplicate BC-managed scopes are surfaced as redundancy advisories before rule sets grow unnecessarily;
- standard users may inspect `firewall_conflicts`; no privileged mutation is needed to read posture;
- firewall drift/conflict events now produce a dedicated GUI alert that opens Protection but never auto-reconciles;
- pywin32 COM lifecycle is explicitly cleaned before apartment teardown to suppress deferred `IUnknown` release noise;
- scanner PE parsing is gated by the actual `MZ` file magic rather than filename extension, preserving renamed-PE coverage while removing exception-heavy parser attempts on ordinary files;
- Windows acceptance adds beta.2 side-effect-free gates for mutation rate limiting, conflict analysis and Threat Decision flow;
- live acceptance requires conflict posture with zero blocking conflicts and exposes abuse-protection metrics.

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

### v0.7.0-beta.3 — Firewall Acceptance Canonicalization (native Windows accepted)
- fixes the native Beta 2 false negative where Windows COM round-trips an IPv4 host such as `192.0.2.77` as `192.0.2.77/255.255.255.255`;
- acceptance now compares remote endpoints semantically rather than by raw string representation;
- the probe also verifies exact BC Sentinel ownership, logical rule id, direction, protocol, port/application scope and enabled state;
- release version advances to Beta 3 so an installed Beta 2 can be exercised through a real transactional `upgrade`; same-version validation remains `repair` only;
- anti-downgrade remains fail-closed and unchanged.

### v0.7.0-beta.2 — Managed Firewall Foundation
- beta.1 native Windows acceptance proved BLOCK rule creation and Windows Firewall enforcement, but exposed immediate rule-observability and test-cleanup defects;
- beta.2 adds stable logical rule identity across management representations, machine-readable Description identity, propagation-aware verification and transactional acceptance cleanup;
- baseline rule-set restoration is now a release gate;

### v0.7.0-beta.1 — Managed Firewall Foundation
- Windows Firewall integration through the documented `INetFwPolicy2`/`HNetCfg` user-mode COM surface;
- BC Sentinel-owned rule namespace/group only;
- BLOCK rules only in the first beta — no automatic ALLOW/open-port behavior;
- IPv4/IPv6 host and CIDR remote blocking;
- inbound/outbound scope, TCP/UDP/ANY protocol and optional remote port;
- optional per-application executable scope;
- explicit approval + existing UAC broker for all mutations;
- read-only firewall status/rule enumeration for standard users;
- managed rule enable/disable without changing global Windows Firewall defaults;
- firewall actions emitted into the existing event/correlation/incident pipeline;
- protected service audit trail for every privileged firewall action;
- live Windows acceptance plus temporary TEST-NET block/remove validation.

### v0.7.x hardening
- rollback/fault-injection acceptance for v0.6.2 updater before final freeze;
- ✅ v0.7.1-beta.1: firewall rule drift detection and explicitly approved reconciliation;
- ✅ v0.7.1-beta.2: rate limiting for firewall mutations and IPC abuse resistance;
- ✅ v0.7.1-beta.2: policy conflict detection;
- ✅ v0.7.1-beta.3: signed local IOC denylist ingestion;
- ✅ v0.7.1-beta.3: safe IOC/incident-qualified network containment with reversible TTL leases;
- ✅ v0.7.1-beta.3: persistent Security Center Inbox for unresolved HIGH/CRITICAL detections;
- ✅ v0.7.2-beta.1: Web Protection / Anti-Phishing foundation with PID-scoped DNS ETW correlation and signed-domain IOC decisions;
- ✅ v0.7.2-beta.2: active reversible Web Protection with persistent findings, shared-IP guard and UAC-backed temporary containment;
- v0.7.2-beta.3: exact-domain trust, signed-IOC precedence, reputation provenance and browser/process context;
- WFP user-mode telemetry research/prototype for deeper future enforcement;
- performance/latency benchmarking under large rule sets.


### v0.7.2-beta.4 — Browser Download Protection & Web Incident Chain
- same-PID exact-browser domain/network → file download provenance;
- persistent BCD download records with independent origin and file verdicts;
- realtime scanner verdict linkage without origin-driven auto-quarantine;
- downloaded-file execution evidence feeding the incident pipeline;
- Security Center Download Protection view;
- no MITM HTTPS or browser extension yet.

## v0.8 — Signed Threat Intelligence & Secure Update Channel
- signed/versioned YARA, behavioral and IOC packages;
- publisher/signature/hash verification;
- staged activation and last-known-good rollback;
- secure application/service updater foundation;
- signed reputation/denylist feed format;
- update transparency/audit metadata.

## v0.9 — Antispyware & Advanced Antimalware
- spyware/adware/PUP detection;
- persistence hunting;
- browser hijack detection;
- credential-stealer indicators;
- suspicious scheduled tasks/services/startup entries;
- remediation plans tied to incident evidence;
- Ransomware Shield 2.0 and protected recovery journal.

## v0.10 — Web Protection, Anti-Phishing & Anti-Truffa — Mature Expansion
- malicious URL/domain reputation;
- phishing and clone-site detection;
- scam/fraud heuristics;
- DNS/network-layer blocking where appropriate;
- download risk interception;
- optional browser companion/extension;
- correlation of browser → domain → download → process → incident.

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
- network-flow and packet/stream detection research on Windows Filtering Platform;
- signature + behavioral intrusion detection;
- prevention/blocking policies with explicit safety gates;
- brute-force, password-spraying and credential-stuffing detection;
- adaptive throttling/rate limiting;
- IP/ASN reputation and account↔device↔network correlation;
- RDP/remote-service protection and post-login anomaly correlation;
- Wireshark used for development/validation and packet analysis, not as the production IPS engine.

## v0.14 — Privacy Protection & Safe Banking
- webcam access monitoring and alerts;
- microphone access monitoring and alerts;
- per-application allow/block policy where supported;
- suspicious privacy-access correlation with EDR;
- Safe Banking protected-session design;
- browser/process interference detection;
- keylogger/injection protections where technically supportable without unsafe hooks;
- protected DNS/network posture checks for financial sessions.

## v0.15 — Identity Protection, Password Manager & 2FA
- encrypted local vault;
- password health and reuse checks;
- breach-monitoring integration with privacy-preserving design;
- TOTP/2FA support;
- clipboard/credential-access hardening;
- identity-risk events feeding EDR/incident correlation.

## v0.16 — VPN & Untrusted-Network Protection
- integrated or tightly controlled companion VPN;
- kill switch;
- secure DNS;
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
