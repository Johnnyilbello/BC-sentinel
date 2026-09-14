# BC Sentinel v0.11.0-beta.6 — B6-4 Implementation Status

Status: **B6-4 THREAT CARD FOUNDATION WINDOWS CI GREEN / LIVE WINDOWS THREAT CARD ACCEPTANCE PENDING**

Primary branch:

```text
feature/v011-beta6-b64-threat-cards
```

Parent stable checkpoint:

```text
B6-3 Smart Scan
f9fab1768d6a4c185ff3a83f01e4a6ed90aaf81c
```

B6-4 is **not stable yet**. `main`, `checkpoint/v011-beta6-b63-pass` and `stable/v011-beta6-b63` remain the accepted promotion state until the B6-4 live Windows acceptance and final stabilization gate are complete.

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

Static B6-4 contract currently reports:

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

Added:

```text
tests/test_v011_beta6_b64_threat_cards.py
tests/test_v011_beta6_b64_window.py
```

Coverage includes:

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

## Windows CI — FOUNDATION PASS

Workflow:

```text
B6-4 Threat Cards Gate
```

Latest explicitly observed full run for the current implementation foundation:

```text
Run: 34841323180
Head: 1e0a99d991e1dcb119259c8d6a2c602206ce1f4b
Result: success
Regression suite: 122 passed, 36 warnings
```

All workflow stages passed:

- compile B6-4 + predecessor modules;
- B6-0 through B6-4 deterministic regression suite;
- B6-3 predecessor acceptance;
- passive B6-4 self-check;
- B6-4 Qt offscreen smoke.

Warnings remain the already known non-blocking PySide `clicked().disconnect()` warnings plus GitHub Actions Node deprecation warnings. They do not represent an accepted security verdict or runtime authority change.

## Live Windows acceptance prepared

Created:

```text
tools/v011_beta6_b64_live_ui_probe.py
RUN-V011-BETA6-B64-LIVE-UI.ps1
```

The probe reuses the already accepted B6-3.5 live UI path but instantiates the B6-4 Home. A valid B6-4 live PASS requires a real `COMPLETED_FINDINGS` Smart Scan and verifies:

- B6-3 live UI contract still passes;
- at least one live finding exists;
- one rendered B6-4 card exists for every returned finding;
- the threat section is visible;
- the first card exposes per-card Advanced details;
- the Advanced payload contains provider provenance and the live finding ID;
- displayed severity equals the canonical result severity;
- displayed confidence equals the canonical result confidence, including `None` when unavailable;
- scan-page and Dashboard horizontal overflow remain zero;
- no destructive authority is present.

If a particular live run happens to return zero findings, that does **not** mean B6-4 failed functionally; it means that run cannot prove the threat-card live requirement and a harmless controlled finding fixture will be required for the acceptance gate.

## Remaining B6-4 stabilization gate

Before B6-4 can be promoted:

1. run the B6-4 live Windows helper against the accepted pinned runtime;
2. obtain at least one live accepted finding and verify it is rendered as a truthful threat card;
3. verify per-card Advanced details against that live finding;
4. commit the supported-Windows acceptance evidence;
5. re-run the final B6-0/B6-1/B6-2/B6-3/B6-4 Windows gate on the final promotion commit;
6. only then create the B6-4 checkpoint/stable refs and advance the roadmap to B6-5.

Do not advance B6-5 before this gate closes.

## Reasoning level

Recommended implementation reasoning: **High**.

Use **Extra High** only if changing canonical severity/confidence semantics, finding classification, or the authority boundary between review and remediation.
