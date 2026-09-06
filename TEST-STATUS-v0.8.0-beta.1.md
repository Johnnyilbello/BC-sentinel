# BC Sentinel v0.8.0-beta.1 — Test Status

## Snapshot under test

Version: `0.8.0-beta.1`

The exact tested source tree is described by `SOURCE-MANIFEST-v0.8.0-beta.1.sha256`.

## Cross-platform regression

Result on the development workspace:

```text
409 passed, 1 skipped
```

The single skip is the native-Windows PowerShell parser acceptance, which is intentionally not executed on the Linux development workspace.

Additional verification:

- `python -m compileall -q sentinel tools tests packaging app` — PASS
- `python -m tools.web_protection_acceptance` — PASS
- `python -m tools.web_threat_response_acceptance` — PASS
- `python -m tools.web_domain_trust_acceptance` — PASS
- `python -m tools.web_download_acceptance` — PASS
- `python -m tools.threat_package_acceptance` — PASS
- application icon DPI/runtime regression — PASS (`5/5` targeted tests)

## Current security acceptance state

The v0.7.x foundations already have native Windows acceptance evidence from the development acceptance cycle. The current `v0.8.0-beta.1` introduces a new signed threat-content/update supply chain and is still a **development preview** until its own native Windows acceptance is completed.

The cross-platform result above must **not** be interpreted as `NATIVE WINDOWS ACCEPTED`.

Native acceptance still needs to validate the installed Windows Protection Service, one-action UAC broker, machine integrity key, native YARA compilation, signed threat-package service path and aggregate `tools.windows_acceptance --service-live` gate.

Expected native regression target for the current source snapshot:

```text
410 passed
```

## Safety invariants verified by the local suite

- signed threat packages are declarative and cannot execute arbitrary code;
- Ed25519 signatures and payload tampering are checked;
- package sequence anti-rollback is enforced;
- rollback is restricted to the recorded Last-Known-Good state;
- threat-content signing and application-release signing use separate trust anchors;
- legacy signed IOC support remains compatible with the v0.8 package overlay;
- Web Protection continues without HTTPS MITM/root-CA injection;
- heuristic-only web signals cannot automatically perform destructive actions;
- firewall mutations remain BC-owned and BLOCK-only;
- shared-IP/CDN containment safety remains fail-closed;
- file verdicts remain independent from download-origin reputation.

## Reproducibility

Use Python 3.12 on Windows and install dependencies from `requirements.txt`. Do not upgrade pip as part of the normal BC Sentinel acceptance workflow unless a specific dependency issue requires it.
