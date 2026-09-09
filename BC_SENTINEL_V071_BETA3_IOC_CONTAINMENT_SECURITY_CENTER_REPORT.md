# BC Sentinel v0.7.1-beta.3 — Security Development Report

## Security objective

Beta.3 turns the existing Threat Decision Center into a persistent decision workflow and adds a local signed IOC trust channel plus reversible, qualification-gated network containment. It deliberately does not add autonomous permanent deletion, global firewall mutation, generic arbitrary privileged network blocking or a cloud dependency.

## Trust and authorization model

1. IOC feeds must validate against a pinned Ed25519 public key.
2. Sequence anti-rollback and expiry checks happen before activation.
3. Feed import is privileged and goes through the existing one-action UAC/Protection Service boundary.
4. Containment is temporary and can be created only for a signed IOC target or a high-confidence incident (score >=70).
5. Every lease is a BC-owned BLOCK rule with an explicit TTL and audit metadata.
6. Pending HIGH/CRITICAL threat decisions are durable; a transient notification is not considered a decision.

## Stale-decision protection

The Inbox does not reuse a stored verdict against whatever happens to exist later at the same path. The current file is rescanned and its SHA-256 must still match the detection identity. A replacement is recorded as superseded and requires a new detection/decision flow.

## Local performance change

YARA can consume already-read bytes for fully buffered small files. This removes duplicate I/O but keeps content reinspection. Hash-cache metadata alone never becomes a security verdict.

## Remaining native validation

The implementation removes lazy Firewall COM enumeration from both the backend and drift acceptance harness. Because the remaining Beta.2 `IUnknown` warning was Windows/pywin32-specific, only the Beta.3 native Windows acceptance can close that item.

## Development verification

Final local regression before packaging:

- `349 passed, 1 skipped` (the skipped case is Windows-native only; expected native target: 350 passed);
- `python -m compileall -q sentinel app tools packaging` PASS;
- signed IOC local acceptance PASS (`signature_verified=true`, `tamper_rejected=true`);
- harmless Threat Decision regression PASS;
- beta.3 aggregate side-effect-free gates PASS.

Local 2,000-file diagnostic benchmark after IOC revision caching and single-read content sampling:

- cold: 0.343 s / 5,839 files/s;
- warm: 0.278 s / 7,188 files/s;
- warm hash-cache hits: 1,980/2,000 (99%);
- warm speedup: 1.231x.

This local benchmark is diagnostic, not a Windows performance claim. Native Windows acceptance remains authoritative.
