# BC Sentinel — macOS Packaging Track

This directory intentionally does **not** contain a fake/partial Mac installer yet.

BC Sentinel's current protection collectors are Windows-specific. The macOS release must first implement and validate the native protection backend described in `ROADMAP.md`, then package the UI + native helper/daemon as one signed distribution.

Planned delivery artifacts:

- signed BC Sentinel `.app`;
- signed flat `.pkg` for components requiring privileged/system installation;
- polished `.dmg` where useful as the distribution wrapper;
- clean uninstaller/removal workflow;
- notarization + stapling;
- Gatekeeper verification;
- upgrade and rollback path.

Prerequisites before this directory gains production build scripts:

1. macOS-native telemetry/protection backend is functional.
2. Required Endpoint Security/System Extension entitlements are approved and provisioned.
3. UI ↔ helper IPC is authenticated and versioned.
4. Apple Silicon target is validated; architecture matrix is explicitly decided.
5. Developer ID Application/Installer identities are available in the release environment.
6. Hardened Runtime and required entitlements are finalized.
7. Notarization workflow is part of CI/release engineering.

Do not ship a `.dmg` that only launches the UI while silently omitting the advertised endpoint-protection capabilities.
