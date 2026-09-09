# BC Sentinel v0.10.0-beta.1 — Full-tree reconstruction note

Date: 8 September 2026

## Why this package exists

The connected GitHub repository contains the v0.10 development delta but not the complete checkpoint-4 source tree. The workspace still had a complete v0.9.0-rc.1 archive and the checkpoint-3/checkpoint-4 audit evidence. This package therefore rebuilds a complete testable tree from that last complete archive and advances it to v0.10.0-beta.1.

## Reconstructed hardening

Checkpoint 3 updater protections implemented in `sentinel/service_update.py`:

- disjoint source/target/backup/staging transaction roots;
- source root and source manifest binding after approval;
- pinned source file reads against the approved manifest;
- process-held update lock;
- sibling staging / previous-deployment rename for atomic restoration;
- protected Windows staging DACL copied from the installed tree;
- schema-2 HMAC-authenticated transaction journals;
- unique temp journal writes with bounded access/sharing retries;
- authenticated backup-manifest binding;
- refusal of modified/rehashed rollback backups;
- refusal of stale rollback over an unrelated release;
- idempotent rollback and recovery.

Checkpoint 4 Authenticode protections implemented in `sentinel/reputation.py`:

- filename never enters PowerShell syntax;
- path and module locations are base64-encoded data decoded inside PowerShell;
- native Windows System32 PowerShell resolved with `GetSystemDirectoryW`;
- Security and Utility modules loaded explicitly from the native PowerShell tree;
- `$PSModuleAutoLoadingPreference='None'`;
- child-only SystemRoot/WINDIR/PSModulePath normalization;
- complete PowerShell script passed through `-EncodedCommand`;
- no execution-policy bypass;
- module/subprocess/JSON failures are fail-closed as `UnknownError` with bounded diagnostics.

## v0.10 delta

The Web Reputation/Phishing layer includes the Unicode tokenizer correction discovered during the user's Windows run and the corrected raw-IP cap assertion. The v0.10 targeted tests now pass 25/25 in this reconstructed tree.

## Validation

- 516 passed, 2 native-Windows skips, 0 failed;
- compileall PASS;
- v0.10 local acceptance PASS.

## Important distinction

This package is a security-equivalent reconstruction based on the documented checkpoint invariants and the last complete source archive available here. It does **not** claim byte identity with the historical checkpoint-4 ZIP or its SHA-256.
