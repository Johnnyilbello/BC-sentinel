# BC Sentinel

> **Windows endpoint security under active development:** antivirus, antispyware, reversible persistence response, behavioral protection, managed firewall, Web Protection, incident response and signed threat intelligence.

## Development status

**Current line:** `v0.9.0-beta.2 — Reversible Persistence Remediation & PUP/Adware Response`

BC Sentinel is a development preview. It is **not production-ready** and should not replace Microsoft Defender, Windows Firewall or a production EDR/NGFW. Keep the native Windows security stack enabled while testing.

The v0.8 release-candidate line completed native Windows acceptance. v0.9 expands BC Sentinel into an antispyware and advanced-antimalware platform while preserving the existing local-first security architecture.

### v0.9 Beta1

Beta1 introduced read-only spyware/persistence discovery and conservative multi-signal scoring across:

- Run / RunOnce and Startup entries;
- Scheduled Tasks;
- automatic Windows services;
- WMI permanent persistence;
- browser policy and forced-extension surfaces;
- proxy and DNS configuration;
- suspicious user-writable, Temp and missing targets;
- Authenticode/provenance and file/network correlation.

The dedicated Beta1 native service acceptance passed. Full aggregate Windows freeze evidence for Beta1 was not supplied before development moved to Beta2.

### v0.9 Beta2

Beta2 adds the first **explicit reversible response layer**. It can create authenticated remediation plans for suspicious Run/RunOnce entries, Startup items, Scheduled Tasks, automatic services and selected browser policies.

Every plan:

- snapshots the exact original object;
- is authenticated with machine-local `HMAC-SHA256`;
- requires explicit operator approval;
- re-checks the object immediately before mutation and fails closed if it changed;
- can be restored from the recorded original state;
- is compatible with the existing one-action UAC broker.

Safety remains strict:

```text
automatic_remediation          = false
automatic_destructive_action   = false
service_process_termination    = false
```

WMI subscriptions, proxy settings and DNS settings remain **review-only** in Beta2 because their restore semantics are not yet strong enough for the same remediation guarantees.

PUP/adware evidence is advisory. A PUP candidate or suspicious persistence entry does not become malware solely because it exists; HIGH/CRITICAL decisions continue to require stronger qualified evidence.

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
- antispyware/persistence discovery and reversible remediation foundation.

## Core security principles

- deterministic protection does not depend on AI or cloud availability;
- AI, when introduced, remains advisory/explanatory rather than the sole enforcement authority;
- private signing keys are never distributed with release artifacts;
- no HTTPS MITM or injected root CA in the current Web Protection architecture;
- heuristic-only evidence cannot perform destructive response;
- firewall management is BC-owned and BLOCK-only;
- signed IOC evidence has precedence over local trust;
- remote retrieval does not imply staging or activation;
- all privileged mutations remain behind authenticated service/UAC boundaries.

## Current verification

The packaged `v0.9.0-beta.2` development candidate passed on the extracted release tree:

```text
469 passed, 1 Windows-only skipped
compileall PASS
10/10 local acceptance suites PASS
```

Native Windows target: **470 passed** plus the aggregate Windows acceptance with no critical failures.

See:

- `RELEASE-NOTES-v0.9.0-beta.2.md`
- `BC_SENTINEL_V090_BETA2_REVERSIBLE_REMEDIATION_REPORT.md`
- `TEST-STATUS-v0.9.0-beta.2.md`
- `DEVELOPMENT_STATUS.md`
- `ROADMAP.md`

## Responsible testing

Use harmless fixtures, TEST-NET addresses and disposable VMs. Do not expose an everyday workstation to live malware solely to test a development build.
