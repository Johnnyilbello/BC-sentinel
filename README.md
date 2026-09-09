# BC Sentinel v0.10.0-rc.1

**Current line: Web Protection Consolidation**

RC1 freezes the v0.10 Beta1→Beta3 Web Reputation, Reversible Web Response and Clone Site / Scam-Fraud stack. It adds high-volume benign compatibility and performance acceptance while preserving the existing safety boundaries.

## One-command Windows validation

PowerShell normale:
```powershell
.\TEST-V010-RC1-ALL-NORMAL.bat
```

PowerShell amministratore:
```powershell
.\TEST-V010-RC1-ALL-ADMIN.bat
```

Both master launchers include full regression, real upgrade, real same-version repair and true standard-user -> UAC. **Reboot is the only intentionally deferred gate** until final roadmap acceptance.

Local pre-delivery: **547 passed, 2 Windows-native skipped, 0 failed**; 323 benign compatibility fixtures with zero failures; compileall and RC1 local acceptance PASS.

See `README-RC1-TEST.md`, `TEST-STATUS-v0.10.0-rc.1.md`, `RELEASE-NOTES-v0.10.0-rc.1.md` and `ROADMAP.md`.

BC Sentinel is a **Windows endpoint-security platform under active development**. It combines local-first malware scanning, behavioral monitoring, a hardened Protection Service, managed Windows Firewall controls, Web Protection, incident response, signed threat intelligence, antispyware/persistence analysis and the new Web Reputation / Phishing Detection foundation in one explainable pipeline.

> **Development preview:** BC Sentinel is not production-ready and is not a replacement for Microsoft Defender, Windows Firewall or a production EDR/NGFW. Keep the native Windows security stack enabled while testing.

## Historical reconstruction baseline

**v0.10.0-beta.1 — Web Reputation & Phishing Detection Foundation**

This complete test candidate was reconstructed from the latest complete v0.9.0-rc.1 archive available to the workspace, brought forward with the documented checkpoint-3 updater and checkpoint-4 Authenticode hardening invariants, then advanced with the v0.10 Beta1 delta.

It is **not claimed to be byte-identical** to the historical checkpoint-4 artifact. The reconstructed tree has its own validation evidence:

- full local regression: **516 passed, 2 Windows-native skips, 0 failed**;
- v0.10 targeted tests: **25 passed**;
- reconstructed checkpoint-3 updater tests: **6 passed**;
- reconstructed checkpoint-4 Authenticode tests: **4 passed + 1 Windows-native skip**;
- Python `compileall`: **PASS**;
- v0.10 local acceptance: **PASS**.

The two local skips require native Windows and are intentionally left for the user's machine. Elevated/live/UAC/upgrade/repair/reboot evidence remains open until the corresponding Windows runs are completed.

See:

- `RECONSTRUCTION-NOTE-v0.10.0-beta.1.md`
- `TEST-STATUS-v0.10.0-beta.1.md`
- `RELEASE-NOTES-v0.10.0-beta.1.md`
- `ROADMAP.md`
- `SECURITY-AUDIT-2026-09-08-V010-BETA1-RECONSTRUCTED-CHECKPOINT2.md`

## Test this package

### 1. PowerShell normale

From the extracted project root:

```powershell
.\TEST-V010-NORMAL.ps1
```

This creates the virtual environment when needed, installs the pinned project requirements without upgrading pip, runs the complete local test suite, v0.10 acceptance and `compileall`.

### 2. PowerShell come amministratore

Only after the normal test is green:

```powershell
.\TEST-V010-ADMIN.ps1
```

This runs the Windows-native acceptance path, fresh Protection Service build/install, live v0.10 checks and service hardening benchmark.

Do not mark the remaining standard-user UAC / upgrade / repair / reboot gates as passed until their dedicated evidence is collected.

## v0.10 Beta1 security model

- local/offline URL and domain reputation primitives;
- IDN/Punycode and mixed-script analysis;
- Unicode look-alike/confusable identity evidence;
- edit-distance-one typosquat detection;
- declared identity kept separate from observed/canonical domain evidence;
- raw-IP, URL userinfo, deep-subdomain and redirect-chain context;
- conservative phishing/scam lure heuristics gated by independent structural risk;
- stable `WDR-*` heuristic fingerprints for deterministic deduplication;
- signed IOC precedence over local exact-domain trust and heuristics;
- heuristic score hard-cap at 49;
- no heuristic-only HIGH/CRITICAL;
- no heuristic auto-block;
- no HTTPS MITM, root CA, TLS interception or mandatory cloud dependency.

## Preserved security lineage

The source tree retains the previously developed v0.3.1→v0.9 architecture: path/reparse hardening, reputation and behavioral correlation, incidents and guarded response, authenticated Protection Service IPC, service hardening, UAC broker, firewall/web/download protection, Threat Decision Center, signed threat packages, secure update/recovery, antispyware/persistence remediation and fileless/advanced antimalware correlation.

The reconstructed checkpoint-3 updater additionally preserves disjoint transaction roots, approved source/manifest binding, pinned source reads, process locking, sibling promotion/restoration, authenticated schema-2 journals, verified rollback identity and idempotent recovery. The reconstructed checkpoint-4 Authenticode path treats filenames only as data, pins native PowerShell/module selection, disables module autoload and fails closed on inspection errors.

## Source synchronization

The connected GitHub branch `v0.10.0-beta.1` is a development delta and does **not** contain this full reconstructed tree. This ZIP is the complete candidate intended for the next native Windows validation. After that evidence is green, the full tree can be synchronized to GitHub before proceeding with the roadmap.
