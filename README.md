# BC Sentinel

> **Windows endpoint security under active development:** antivirus, antispyware, reversible persistence response, advanced antimalware correlation, behavioral protection, managed firewall, Web Protection, incident response and signed threat intelligence.

## Development status

**Current line:** `v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation`

BC Sentinel is a development preview. It is **not production-ready** and should not replace Microsoft Defender, Windows Firewall or a production EDR/NGFW. Keep the native Windows security stack enabled while testing.

The `v0.8.0-rc.1` line completed native Windows acceptance. `v0.9.0-beta.1` and `v0.9.0-beta.2` are also recorded as native Windows accepted baselines. Beta3 extends the antispyware/remediation foundation with a conservative advisory antimalware layer for fileless and dual-use Windows execution chains.

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

Beta3 adds the `AdvancedAntimalwareEngine` for explainable correlation of:

- PowerShell and script-host command context;
- bounded encoded/dynamic and in-memory execution indicators;
- Windows LOLBins including MSHTA, Rundll32, Regsvr32, Certutil, BITSAdmin, MSIExec, WMIC and CMSTP patterns;
- Office/browser/script-host parent-child relationships;
- short-lived same-PID process → network chains;
- deterministic file/IOC evidence that can strengthen an existing behavioral chain;
- ATT&CK-style technique identifiers, confidence, provenance and persistent findings.

A single dual-use Windows tool is **not malware by identity**. One evidence family cannot qualify HIGH on its own. Stronger outcomes require converging independent evidence or qualified deterministic evidence.

Beta3 introduces **no automatic process termination, file deletion, quarantine or persistence mutation**. Existing Threat Decision, quarantine and reversible-remediation boundaries remain unchanged.

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
- AI, when introduced, remains advisory/explanatory rather than the sole enforcement authority;
- private signing keys are never distributed with release artifacts;
- no HTTPS MITM or injected root CA in the current Web Protection architecture;
- heuristic-only evidence cannot perform destructive response;
- firewall management is BC-owned and BLOCK-only;
- signed IOC evidence has precedence over local trust;
- remote retrieval does not imply staging or activation;
- all privileged mutations remain behind authenticated service/UAC boundaries;
- dual-use administration tools are not classified as malware by executable name alone.

## Current verification

The exact extracted `v0.9.0-beta.3` release tree was rechecked during the repository update:

```text
477 passed, 1 Windows-only skipped
compileall PASS
```

Beta3 is therefore **ready for native Windows acceptance**, but this repository update does not claim that the Beta3 native freeze has already passed.

Release SHA-256:

```text
36d7fe86b8741567c67505b7ccb429915afe89d5bff5ac95b6f61d56e17c32eb
```

See:

- `RELEASE-NOTES-v0.9.0-beta.3.md`
- `BC_SENTINEL_V090_BETA3_ADVANCED_ANTIMALWARE_REPORT.md`
- `BC_Sentinel_Roadmap_v0_9_0_Beta3_Updated.md`
- `TEST-STATUS-v0.9.0-beta.3.md`
- `RELEASE-SHA256-v0.9.0-beta.3.txt`
- `DEVELOPMENT_STATUS.md`
- `ROADMAP.md`

## Next milestone

`v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening`

The RC phase is intended to consolidate Beta1–Beta3, harden false-positive boundaries, exercise clean install/upgrade/repair and rollback matrices, and freeze v0.9 only after native Windows regression succeeds.

## Responsible testing

Use harmless fixtures, TEST-NET addresses and disposable VMs. Do not expose an everyday workstation to live malware solely to test a development build.
