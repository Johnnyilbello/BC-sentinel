# BC Sentinel — Product & Security Roadmap

**Current development line:** `v0.8.0-beta.1 — Signed Threat Intelligence & Secure Update Channel`

BC Sentinel is evolving from an antivirus MVP into an integrated Windows endpoint-security suite. Antivirus, firewall, Web Protection, incident response, EDR, sandbox, IDS/IPS, privacy and identity protections are intended to feed one explainable event/correlation/incident pipeline. Deterministic protection must remain functional without AI or a cloud model.

## Accepted foundation

### v0.3.1 — Security Hardening
PID-reuse-safe identity, stronger ETW attribution, path/reparse hardening, quarantine integrity/race protections, allowlists and hash-cache hardening.

### v0.4.x — Reputation, Network Intelligence & Behavioral Correlation
Local file prevalence, Authenticode context, process-to-connection attribution, endpoint reputation and bounded multi-signal behavioral correlation.

### v0.5.0 — Incident Correlation & Response
Consolidated incidents, bounded timelines, persistent response audit, guarded process response and encrypted quarantine.

### v0.6.x — Windows Protection Service & Tamper Resistance
Windows service, authenticated local Named Pipe IPC, kernel-derived client identity, Program Files deployment, ACL/SCM/config hardening, authenticated integrity manifest, one-action UAC broker and transactional upgrade/repair with rollback.

## v0.7 — Firewall & Web Protection foundation

Completed development in the v0.7 line includes:

- BC Sentinel-managed Windows Firewall BLOCK-only rules;
- drift detection and explicitly approved reconciliation;
- mutation/IPC rate limiting and policy-conflict analysis;
- Ed25519-signed IOC feed ingestion and anti-rollback;
- reversible incident/IOC-qualified network containment leases;
- persistent Security Center Inbox;
- DNS Client ETW and PID-scoped domain/network correlation;
- anti-phishing structural heuristics with no heuristic auto-block;
- persistent Web Findings;
- shared-IP/CDN fail-closed containment guard;
- exact-domain local trust with signed-IOC precedence;
- local domain reputation provenance and browser process context;
- browser download tracking and browser → domain → connection → download → file → process → incident correlation.

Remaining lower-level research from the v0.7 era includes deeper WFP telemetry/enforcement prototyping and large-rule-set performance testing.

## v0.8 — Signed Threat Intelligence & Secure Update Channel

### v0.8.0-beta.1 — current

Implemented:

- separate Ed25519 trust anchors for threat content and application-release provenance;
- declarative `bcsentinel.threat-package.v1` format for bounded IOC, YARA and advisory behavioral metadata;
- canonical signature verification, component hashes, validity windows and minimum-product-version checks;
- sequence high-water anti-rollback and sequence-reuse protection;
- staging validation and YARA compilation before activation on the production dependency set;
- machine-HMAC authenticated activation state and transparency history;
- atomic activation and one-step last-known-good rollback;
- threat-package IOC overlay feeding the existing scanner/network/web decision paths;
- YARA hot reload with last-compiled fail-safe behavior;
- advisory-only behavior content with no script/command execution surface;
- `bcsentinel.release-envelope.v1` publisher envelope for future signed application/service updates;
- exact update file-set, SHA-256 and size verification with unsafe path/reparse rejection;
- one-action UAC package installation through the Protection Service.

Remaining v0.8 work:

- external/offline signing pipeline;
- key rotation and revocation policy;
- signed reputation package family;
- fault-injection and interrupted-activation recovery across restart/reboot;
- secure remote retrieval, resumable transport and freshness policy;
- make publisher signatures mandatory for distributed application/service updates once signing infrastructure is operational;
- bounded signed behavioral policy integration with dedicated native acceptance;
- release transparency/provenance export and operational recovery runbooks.

## v0.9 — Antispyware & Advanced Antimalware

Planned:

- spyware/adware/PUP detection;
- persistence hunting;
- browser hijack detection;
- credential-stealer indicators;
- suspicious scheduled tasks/services/startup entries;
- evidence-linked remediation;
- Ransomware Shield 2.0 and protected recovery journal.

## v0.10 — Mature Web Protection, Anti-Phishing & Anti-Scam

Planned:

- richer malicious URL/domain reputation;
- phishing and clone-site detection;
- scam/fraud heuristics;
- DNS/network-layer prevention where safe;
- download risk interception;
- optional browser companion/extension;
- richer browser → domain → download → process → incident correlation.

## v0.11 — EDR Core

Planned:

- durable endpoint activity timeline;
- process/file/network/persistence identity graph;
- IOC hunting and retrospective search;
- root-cause/process-tree incident views;
- reversible host/network containment;
- explainable automated response policies;
- enterprise policy and audit foundation.

## v0.12 — Sandbox & Dynamic Analysis

Planned isolated suspicious-file execution with filesystem, registry, process and network diffing, behavioral scoring and strict resource/network controls. Unknown samples must not be detonated directly on the protected host OS.

## v0.13 — IDS/IPS & Credential-Attack Protection

Planned:

- Windows Filtering Platform network-flow/packet research;
- signature and behavioral intrusion detection;
- prevention policies with explicit safety gates;
- brute-force, password-spraying and credential-stuffing detection;
- adaptive throttling/rate limiting;
- IP/ASN reputation and account/device/network correlation;
- RDP/remote-service protection and post-login anomaly correlation.

## v0.14 — Privacy Protection & Safe Banking

Planned webcam/microphone access controls, privacy anomaly correlation, protected banking-session design, browser/process interference detection, and keylogger/injection defenses where technically supportable without unsafe hooks.

## v0.15 — Identity Protection, Password Vault & 2FA

Planned encrypted local vault, password health/reuse checks, privacy-preserving breach monitoring, TOTP/2FA and credential-access hardening.

## v0.16 — VPN & Untrusted-Network Protection

Planned integrated/controlled VPN companion, kill switch, secure DNS, untrusted Wi-Fi protection and per-application routing/policy where supported.

## Later milestones

### macOS Native Protection Foundation
Only after a real native backend using supported Apple security APIs and a signed/notarized helper lifecycle.

### Production Packaging
Signed Windows GUI/service/broker binaries, production installer upgrade/repair/uninstall, secure updater bootstrap, release provenance and reproducible release checks.

### v1.0 — Production Endpoint Protection Suite
BC Sentinel reaches v1.0 only after protected service boundaries, secure signed updates, false-positive/compatibility testing, rollback/runbooks and native acceptance evidence for every advertised capability.
