# BC Sentinel

> **Windows endpoint security platform under active development.** BC Sentinel is a local-first security project that brings antivirus, behavioral monitoring, managed firewall controls, Web Protection, incident response and signed threat intelligence into one explainable protection pipeline.

## Development status

**Current development line:** `v0.8.0-beta.1 — Signed Threat Intelligence & Secure Update Channel`

**Status:** active development / development preview.

BC Sentinel is **not production-ready yet** and is **not a replacement for Microsoft Defender, Windows Firewall or a production EDR/NGFW**. Keep the native Windows security stack enabled while testing.

The current `v0.8.0-beta.1` source snapshot is being validated as the next development milestone. Earlier v0.7.x security foundations have completed native Windows acceptance, while v0.8 introduces a new signed threat-content and secure-update supply chain that must complete its own Windows acceptance before it is frozen as accepted.

The current source candidate has completed the cross-platform regression with **409 passed, 1 Windows-only skip**, `compileall` PASS and all five local acceptance gates PASS. This does **not** replace the required native Windows service/UAC/YARA acceptance. See `TEST-STATUS-v0.8.0-beta.1.md` and `SOURCE-MANIFEST-v0.8.0-beta.1.sha256` for the exact tested snapshot.

## What BC Sentinel is

BC Sentinel started as an antivirus MVP and is evolving into an integrated Windows endpoint-security suite. The project is designed around one shared event, correlation and incident pipeline instead of isolated protection modules.

Current capabilities include:

- static malware scanning with SHA-256 identity, YARA and PE-aware analysis;
- realtime filesystem protection;
- ransomware and behavioral shields;
- encrypted quarantine, restore and explicit Threat Decision workflows;
- Windows Protection Service running under a hardened service boundary;
- authenticated local Named Pipe IPC and one-action UAC broker;
- install-tree/configuration integrity checks, ACL/SCM hardening and tamper detection;
- process, file and network attribution with ETW-based telemetry;
- behavioral correlation and persistent incident timelines;
- BC Sentinel-managed Windows Firewall **BLOCK-only** rules;
- firewall drift detection, reconciliation, policy-conflict analysis and abuse-rate limiting;
- Ed25519-signed IOC feeds with anti-rollback controls;
- reversible incident-driven network containment leases;
- DNS/process-correlated Web Protection without HTTPS MITM;
- signed-domain threat decisions and shared-IP/CDN safety guards;
- exact-domain local trust with strict precedence: **signed IOC > local trust > heuristics**;
- browser/process context and browser-download provenance;
- browser → domain → connection → download → file → process → incident correlation;
- persistent Web Findings and Security Center workflows;
- signed threat-package staging/activation with last-known-good rollback;
- separate trust anchors for threat content and future application-release signing.

## v0.8.0-beta.1

The v0.8 line introduces a declarative signed security-content channel.

Threat packages can contain bounded security data such as:

- IOC indicators;
- YARA rules;
- advisory behavioral metadata.

Packages are verified before activation using Ed25519 signatures, canonical payload validation, validity windows, component hashes and sequence-based anti-rollback controls. Content is validated in staging and published atomically. A lower sequence cannot be activated arbitrarily; rollback is restricted to the recorded **last-known-good** package.

The v0.8 architecture intentionally does **not** allow threat packages to execute arbitrary code, scripts or shell commands.

A separate signed application-release envelope is also being introduced for the future production updater. The development `BUILD -> Upgrade/Repair` workflow remains compatible while external production signing infrastructure is still being built.

## Security principles

BC Sentinel follows several non-negotiable rules:

- deterministic protection must work without AI or a cloud model;
- AI, when used in the future, is advisory/explanatory rather than the only security decision-maker;
- no HTTPS MITM, injected root CA or transparent TLS decryption in the current Web Protection architecture;
- no heuristic-only destructive response;
- quarantine/delete actions require qualified file verdicts and explicit protected decision paths;
- firewall management is BC-owned and BLOCK-only; global Windows Firewall policy and third-party rules are not modified;
- local domain trust cannot override an active signed malicious IOC;
- DNS-only observations are insufficient for domain-to-IP containment: a matching real connection and safety checks are required;
- private signing keys are never distributed with the application.

## Local-first architecture

BC Sentinel is designed so that core protection remains available locally. External threat-intelligence, remote retrieval and cloud services are not required for the deterministic protection engine in the current development line.

Mutable service state is stored under:

```text
%PROGRAMDATA%\BCSentinel\Protection
```

The hardened Protection Service deployment lives under:

```text
%ProgramFiles%\BC Sentinel\Protection
```

## Development setup

Target environment: **Windows 11 / Python 3.12**.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the test suite with an isolated temp directory:

```powershell
$PytestTemp = Join-Path $env:TEMP "bc-sentinel-pytest"
Remove-Item $PytestTemp -Recurse -Force -ErrorAction SilentlyContinue
.\.venv\Scripts\python.exe -m pytest -q --basetemp "$PytestTemp"
```

Do not upgrade pip as part of the normal BC Sentinel acceptance workflow unless there is a specific reason to do so.

## Build the Protection Service

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\BUILD-SERVIZIO-PROTEZIONE.ps1
```

The protected build contains the Windows service, one-action UAC broker and the authenticated integrity manifest used by the upgrade/install process.

## Current acceptance model

BC Sentinel uses explicit release gates instead of assuming that a feature works because unit tests pass. Releases are exercised through:

- full pytest regression;
- Windows-native service acceptance;
- updater/repair acceptance;
- firewall and drift acceptance;
- IOC and containment acceptance;
- Web Protection / Web Threat Response acceptance;
- Domain Trust and browser/download-chain acceptance;
- security and performance benchmarks.

For the current v0.8 development snapshot, see:

- `TEST-STATUS-v0.8.0-beta.1.md`
- `SOURCE-MANIFEST-v0.8.0-beta.1.sha256`
- `RELEASE-NOTES-v0.8.0-beta.1.md`
- `BC_SENTINEL_V080_BETA1_SIGNED_THREAT_INTELLIGENCE_REPORT.md`
- `BC_Sentinel_Roadmap_v0_8_0_Beta1_Updated.md`
- `ROADMAP.md`

## Roadmap

Major planned development phases include:

1. **v0.8** — signed threat intelligence, key lifecycle and secure update channel;
2. **v0.9** — antispyware and advanced antimalware;
3. **v0.10** — mature Web Protection, anti-phishing and anti-scam protection;
4. **v0.11** — EDR core and endpoint identity graph;
5. **v0.12** — isolated sandbox and dynamic analysis;
6. **v0.13** — IDS/IPS plus brute-force, password-spraying and credential-stuffing protection;
7. **v0.14** — webcam/microphone privacy controls and Safe Banking;
8. **v0.15** — identity protection, password vault and 2FA;
9. **v0.16** — VPN and untrusted-network protection;
10. **v1.0** — production endpoint protection suite, only after native acceptance, secure packaging, update signing, compatibility testing and operational runbooks are complete.

## Responsible testing

Do **not** test BC Sentinel with real malware on an everyday Windows installation. Use harmless fixtures such as EICAR where appropriate, TEST-NET addresses, or an isolated disposable virtual machine.

## Project note

This repository documents and tracks an **actively developed security product**. Interfaces, internal schemas and implementation details may change between beta releases while safety, compatibility and native Windows acceptance are being hardened.
