# BC Sentinel v0.7.1-beta.2 — Firewall Abuse Resistance, Policy Conflicts & Threat Decision E2E

## Scope

This release hardens the native-Windows-accepted v0.7.1-beta.1 drift/reconciliation line without weakening the accepted v0.7.0 firewall foundation. BLOCK-only ownership, global-policy non-interference, one-action UAC, anti-downgrade, transactional upgrade/repair and explicit operator approval remain unchanged.

## Privileged mutation rate limiting

The Protection Service now applies identity-scoped sliding-window limits to sensitive actions:

- firewall mutation/reconciliation bursts;
- quarantine/restore/threat-response actions;
- exclusion changes;
- one-action UAC ticket preparation;
- other privileged service mutations.

Limits are keyed to the transport-authenticated Windows SID/session/transport context. `privileged_ticket_result` polling is excluded so a normal UAC flow cannot rate-limit itself while waiting for the broker result. Exceeded limits fail closed with `rate_limited` plus bounded cooldown metadata.

## IPC abuse resistance

Repeated malformed IPC messages are counted separately from valid requests. A local client context that floods malformed JSON/messages is temporarily rate-limited. The service exposes aggregate limiter metrics only; no secrets, active ticket identifiers or payloads are exposed.

## Firewall Policy Conflict Engine

New read-only `firewall_conflicts` posture separates:

- **blocking conflicts** — exact BC Sentinel managed-group collisions / inspection failures that violate the ownership gate;
- **advisories** — exact remote-host/network overlaps with enabled external ALLOW rules and duplicate BC-managed scopes.

External ALLOW overlaps remain advisory because Windows BLOCK precedence is retained. BC Sentinel never edits the external rule, never creates ALLOW rules and never changes global/default firewall policy.

## Firewall GUI alerting

`rule_drift_detected` and `policy_conflict_detected` events now surface a dedicated GUI alert explaining the evidence and allowing the user to open Protection. The dialog is read-only; reconciliation still requires the existing explicit privileged action.

## Threat Decision Center — service-owned execution

The existing decision card now reaches the privileged service boundary when the Protection Service owns protection:

- **Quarantena · consigliato** → service-side encrypted quarantine;
- **Elimina definitivamente** → service-side identity-safe permanent delete;
- **Mantieni questa volta** → no persistent trust;
- **Consenti hash** → exact SHA-256 allowlist through the privileged broker plus local UI state synchronization.

A new `threat_file_action` protocol operation carries the exact expected SHA-256, score, level and bounded evidence list. Quarantine/delete refuse a stale decision if the current file bytes no longer match the detected digest. The privileged endpoint additionally refuses file actions unless the detection is qualified as HIGH/CRITICAL with score >=70, so it cannot be repurposed as a generic privileged file remover. The local fallback path keeps the same hash/snapshot protections.

Permanent deletion remains manual-only and is never triggered automatically by a detector in this release. BC Sentinel-managed files and files inside the protected Windows system tree are refused by quarantine/delete response paths.

## Harmless Threat Decision acceptance

`tools.threat_decision_acceptance` uses temporary harmless fixtures only and validates:

1. simulated EICAR-class CRITICAL detection;
2. quarantine with expected SHA-256;
3. encrypted restore with exact content verification;
4. identity-safe permanent delete;
5. keep-once does not create allowlist state;
6. allow-hash trusts the original digest but not changed bytes.

## Scanner performance hardening

PE parsing no longer invokes `pefile` on every ordinary file. The scanner first checks the actual `MZ` magic and only then enters PE parsing. This keeps coverage for renamed PE files while avoiding exception-heavy parser attempts on text/data files.

Benchmark output now includes hash-cache hit ratio, warm/cold speedup and the cache security mode. BC Sentinel still reinspects deterministic content; this change does not introduce a metadata-only verdict cache.

## COM lifecycle cleanup

The Windows Firewall COM backend explicitly releases its policy/rule references before `CoUninitialize`, with a bounded garbage-collection cleanup. This targets the non-fatal `IUnknown` release noise observed during native drift acceptance without changing firewall semantics.

## Acceptance additions

The Windows acceptance harness adds critical gates for:

- privileged firewall mutation burst limiting;
- policy conflict engine semantics;
- harmless Threat Decision end-to-end flow;
- live `firewall_conflicts` posture with zero blocking conflicts;
- live abuse-protection metric exposure.

## Safety properties retained

- BC Sentinel firewall mutation remains BLOCK-only;
- no global firewall enable/disable;
- no default inbound/outbound policy mutation;
- no third-party rule mutation;
- no automatic permanent malware deletion;
- no publisher-wide trust from a single detection;
- anti-downgrade remains fail-closed;
- quarantine remains encrypted and reversible;
- delete/quarantine require current-file identity validation;
- destructive response is restricted to qualified HIGH/CRITICAL detections and protected Windows/BC Sentinel paths fail closed.

## Development verification

- full suite: **331 passed, 1 skipped** on the non-Windows development host; the skip is the native Windows-only parser gate;
- Python `compileall`: PASS;
- harmless Threat Decision acceptance: PASS;
- beta.2 side-effect-free security gates: PASS;
- 2,000-file development benchmark: warm scan **1.252x** cold throughput with 1,980 hash-cache hits (99% hit ratio);
- native Windows upgrade/build/live acceptance remains the release freeze gate.
