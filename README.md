# BC Sentinel

> **Windows endpoint security under active development:** antivirus, antispyware, reversible persistence response, advanced antimalware correlation, behavioral protection, managed firewall, Web Protection, incident response and signed threat intelligence.

## Development status

**Frozen line:** `v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening`

BC Sentinel remains a development preview. It is **not production-ready** and should not replace Microsoft Defender, Windows Firewall or a production EDR/NGFW. Keep the native Windows security stack enabled while testing.

The v0.9 line has completed its release-candidate freeze on the target Windows machine. The RC1 baseline passed the complete Python suite, native foundation acceptance, native build, upgrade, live-service acceptance, repair, service-hardening benchmark and post-reboot live acceptance.

### v0.9 Beta1 — Antispyware foundation

Beta1 introduced spyware/persistence discovery and conservative multi-signal scoring across Run/RunOnce, Startup, Scheduled Tasks, automatic services, WMI permanent persistence, browser policy/forced-extension surfaces, proxy/DNS configuration and executable provenance.

### v0.9 Beta2 — Reversible persistence response

Beta2 added HMAC-authenticated remediation plans with exact pre-mutation revalidation, explicit approval, reversible restoration and one-action UAC integration for selected persistence surfaces. WMI, proxy and DNS remain review-only where equivalent restore guarantees are not yet available.

Safety remains strict:

```text
automatic_remediation          = false
automatic_destructive_action   = false
service_process_termination    = false
```

### v0.9 Beta3 — Advanced Antimalware & Fileless Correlation

Beta3 added the `AdvancedAntimalwareEngine` for explainable correlation of PowerShell/script-host command context, bounded encoded/dynamic and in-memory indicators, Windows LOLBins, Office/browser/script-host parent-child relationships, short-lived same-PID process → network chains and deterministic file/IOC evidence that may strengthen an existing behavioral chain.

A single dual-use Windows tool is **not malware by identity**. One evidence family cannot qualify HIGH on its own. Stronger outcomes require converging independent evidence or qualified deterministic evidence.

### v0.9 RC1 — Consolidation & Native Hardening

RC1 freezes the v0.9 Beta1→Beta3 model and adds explicit false-positive hardening for administrative/script-heavy workloads. It preserves the existing protected response boundaries and introduces no automatic process termination, file deletion, quarantine or persistence mutation from the Advanced Antimalware layer.

## Existing protection stack

BC Sentinel currently includes:

- realtime and on-demand malware scanning;
- SHA-256 identity, YARA and PE-aware inspection;
- ransomware and behavior shields;
- encrypted quarantine and Threat Decision workflows;
- hardened Windows Protection Service;
- authenticated Named Pipe IPC and one-action UAC broker;
- ETW process/file/network attribution;
- persistent incident timelines and behavioral correlation;
- BC Sentinel-owned Windows Firewall BLOCK-only controls;
- firewall drift/reconciliation and conflict analysis;
- Ed25519-signed IOC and threat-content packages;
- key rotation/revocation and anti-rollback state;
- signed reputation as advisory evidence;
- DNS/process-correlated Web Protection without HTTPS MITM;
- browser/download provenance and Web Incident Chain;
- signed remote threat index and content-addressed threat cache;
- crash-consistent staged threat-content activation;
- antispyware/persistence discovery and reversible remediation;
- advisory advanced-antimalware/fileless correlation.

## Core security principles

- deterministic protection does not depend on AI or cloud availability;
- AI remains advisory/explanatory rather than the sole enforcement authority;
- private signing keys are never distributed with release artifacts;
- no HTTPS MITM or injected root CA in the current Web Protection architecture;
- heuristic-only evidence cannot perform destructive response;
- firewall management is BC-owned and BLOCK-only;
- signed IOC evidence has precedence over local trust;
- remote retrieval does not imply staging or activation;
- all privileged mutations remain behind authenticated service/UAC boundaries;
- dual-use administration tools are not classified as malware by executable name alone.

## v0.9 RC1 verification

Target Windows validation completed on 2026-09-07:

```text
pytest                         482 / 482 PASS
RC1 acceptance                 PASS
Windows foundation             PASS
native build                   PASS
upgrade                        PASS
live-service acceptance        PASS
repair                         PASS
service-hardening benchmark    PASS
post-reboot live acceptance    PASS
```

Release SHA-256:

```text
8a4a2c3e1cc7c9c411d7e25c189d016b29994311a4d991caba30dfa5bc23b350
```

See:

- `RELEASE-NOTES-v0.9.0-rc.1.md`
- `BC_SENTINEL_V090_RC1_CONSOLIDATION_REPORT.md`
- `BC_Sentinel_Roadmap_v0_9_0_RC1_Updated.md`
- `TEST-STATUS-v0.9.0-rc.1.md`
- `WINDOWS-ACCEPTANCE-v0.9.0-rc.1.md`
- `RELEASE-SHA256-v0.9.0-rc.1.txt`
- `DEVELOPMENT_STATUS.md`
- `ROADMAP.md`

## Next milestone

**`v0.10.0-beta.1` — Web Protection / Anti-Phishing / Anti-Scam Mature Expansion Foundation**

The v0.10 line builds on the existing v0.7 DNS/process-correlated Web Protection instead of replacing it. New heuristic/deception signals remain explainable and bounded below destructive-response thresholds unless stronger deterministic evidence exists.

## Responsible testing

Use harmless fixtures, TEST-NET addresses and disposable VMs. Do not expose an everyday workstation to live malware solely to test a development build.
