# BC Sentinel v0.11.0-beta.6 — B6-4 Implementation Status

Status: **B6-4 THREAT CARDS WINDOWS CI GREEN / LIVE WINDOWS ACCEPTANCE PASS / FINAL PROMOTION CI PENDING**

Primary branch:

```text
feature/v011-beta6-b64-threat-cards
```

Parent stable checkpoint:

```text
B6-3 Smart Scan
f9fab1768d6a4c185ff3a83f01e4a6ed90aaf81c
checkpoint/v011-beta6-b63-pass
stable/v011-beta6-b63
```

B6-4 has passed its real-Windows Threat Card acceptance. It is not promoted to checkpoint/stable refs until the final branch-head Windows gate completes successfully.

## Goal

B6-4 turns accepted Smart Scan findings into understandable threat-review cards while preserving the exact underlying security semantics and full technical evidence.

The milestone follows the permanent BC Sentinel information model:

1. plain-language default presentation;
2. complete `Dettagli avanzati` evidence.

It does not introduce a separate expert mode and does not introduce remediation authority.

## Implemented foundation

### Presentation model

`sentinel/home_threat_cards.py`

Profile/schema:

```text
v0.11.0-beta.6-b64
bc-sentinel-beta6-threat-card-v1
```

Implemented:

- one `ThreatCardModel` for each accepted `SmartScanFinding`;
- canonical severity preserved exactly;
- provider/result finding order preserved;
- confidence preserved exactly when `SmartScanFinding.confidence` exists;
- missing confidence shown as `Non disponibile` rather than inferred;
- plain-language location fallback without inventing evidence;
- per-card Advanced details containing exact finding evidence, matching source check result, scan/session context and provider provenance;
- cancelled/incomplete scan state and coverage preserved in every card's technical evidence.

B6-4 does not derive confidence from severity, score, signal count, YARA evidence, or raw historical scanner payloads. Any future confidence propagation must be explicit and separately tested.

### Threat-card UI

`sentinel/home_threat_cards_ui.py`

Implemented:

- `ThreatCardWidget`;
- `B64SmartScanPage` layered on top of the accepted B6-3 Smart Scan page;
- title, canonical severity, reason, category, confidence, source check and location;
- review recommendation;
- accessible per-card `Dettagli avanzati` control;
- complete technical JSON evidence per finding;
- scan-level Advanced details preserved alongside per-card details;
- existing Dashboard visual tokens reused rather than introducing a second visual system;
- path/reason text wraps safely;
- threat cards clear when a new scan starts.

No action buttons for quarantine, delete, process termination, repair or trust/allowlist mutation are exposed.

### Home integration

`sentinel/home_threat_cards_window.py`

`B64SecurityOverviewWindow` inherits the accepted B6-3 Home and replaces only the Smart Scan presentation surface. It keeps the same:

- coordinator;
- fixed provider boundary;
- explicit user start;
- worker-thread execution;
- progress flow;
- cancellation behavior;
- six-page shell;
- disabled Full Scan state;
- non-destructive authority contract.

## Truthfulness contract

B6-4 must never:

- upgrade or downgrade a finding severity;
- synthesize confidence;
- convert heuristic/suspicious evidence into a definitive malware claim;
- hide cancelled/incomplete coverage;
- imply whole-disk cleanliness from bounded Smart Scan scope;
- claim quarantine/repair/deletion when none occurred;
- remove source evidence from Advanced details.

Static B6-4 contract:

```text
severity_mutation=false
confidence_inference=false
automatic_quarantine=false
automatic_repair=false
automatic_destructive_action=false
guided_resolution_enabled=false
per_card_advanced_details=true
scan_level_advanced_details_preserved=true
```

Guided remediation belongs to B6-5 and remains out of scope.

## Deterministic tests

B6-4 coverage:

```text
tests/test_v011_beta6_b64_threat_cards.py
tests/test_v011_beta6_b64_window.py
```

The regression suite covers:

- B6-4 profile/schema and authority contract;
- exact severity preservation;
- exact confidence preservation;
- missing-confidence fail-safe presentation;
- exact finding/source/provider/raw evidence preservation;
- cancelled/incomplete finding presentation without false COMPLETE state;
- per-card Advanced details rendering;
- scan-level Advanced details preservation;
- real B6-4 Home integration;
- six-page shell preservation;
- no horizontal overflow in the B6-4 scan surface;
- no implicit scan dispatch during construction/render tests.

## Windows CI — GREEN

Workflow:

```text
B6-4 Threat Cards Gate
```

Latest observed green run before the promotion-evidence commit:

```text
Run: 34841481988
Head: 7a9cdd8862975b7affee206c8a3006131d490024
Result: success
```

The previous full foundation run recorded:

```text
Run: 34841323180
Head: 1e0a99d991e1dcb119259c8d6a2c602206ce1f4b
Result: success
Regression suite: 122 passed, 36 warnings
```

All required workflow stages passed, including predecessor regression, B6-3 acceptance, passive B6-4 self-check and Qt offscreen smoke. Known PySide `clicked().disconnect()` warnings and GitHub Actions Node deprecation warnings remain non-blocking and do not change security authority.

## Live Windows acceptance — PASS

Acceptance date:

```text
2026-09-14
```

Detailed record:

```text
BC_SENTINEL_V011_BETA6_B64_LIVE_ACCEPTANCE_2026-09-14.md
```

Observed real Smart Scan result:

```text
state: COMPLETED_FINDINGS
coverage: COMPLETE
completed_checks: 5/5
elapsed_ms: 13438
findings_count: 7
highest_severity: HIGH
full_filesystem_coverage: false
no_destructive_authority: true
```

Observed B6-4 presentation acceptance:

```text
card_count: 7
severity_matches_result: true
confidence_matches_result: true
per_card_advanced_available: true
per_card_advanced_payload_present: true
threat_section_visible: true
scan_page_horizontal_scroll_max: 0
dashboard_horizontal_scroll_max: 0
failures: []
passed: true
```

Terminal result:

```text
B6-4 live Threat Cards UI acceptance PASS.
```

This closes the real-Windows finding-to-card and Advanced Details gate. `coverage: COMPLETE` applies only to the declared bounded Smart Scope and must not be represented as whole-filesystem coverage.

## Remaining promotion gate

Only final stabilization remains:

1. run the `B6-4 Threat Cards Gate` on the promotion-evidence branch head;
2. require a green result with predecessor gates preserved;
3. create `checkpoint/v011-beta6-b64-pass` and `stable/v011-beta6-b64` at that accepted head;
4. advance the active development line to B6-5 Guided Resolution.

No additional live B6-4 scan is required unless the final code changes security behavior or invalidates the accepted evidence.

## Reasoning level

Recommended implementation reasoning: **High**.

Use **Extra High** only if changing canonical severity/confidence semantics, finding classification, or the authority boundary between review and remediation.
