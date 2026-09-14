# BC Sentinel v0.11.0-beta.6 — B6-4 Live Windows Acceptance — 2026-09-14

Status: **PASS**

Milestone:

```text
B6-4 — Threat Cards + Advanced Details
```

Branch under test:

```text
feature/v011-beta6-b64-threat-cards
```

## Purpose

This acceptance closes the real-Windows finding-to-Threat-Card requirement for B6-4. It verifies that a real accepted Smart Scan result can be rendered into truthful review cards without changing the underlying security semantics or gaining remediation authority.

## Live Smart Scan evidence

The accepted live run completed with:

```text
state: COMPLETED_FINDINGS
coverage: COMPLETE
completed_checks: 5/5
elapsed_ms: 13438
findings_count: 7
highest_severity: HIGH
no_destructive_authority: true
```

`coverage: COMPLETE` refers only to the declared bounded Smart Scope. The provider explicitly reports:

```text
full_filesystem_coverage: false
scope_mode: risk_prioritized_v1
```

It must not be interpreted as whole-disk cleanliness or whole-filesystem coverage.

The live result also preserved the B6-3 authority boundary:

```text
automatic_destructive_action: false
automatic_quarantine: false
automatic_repair: false
```

## Threat Card acceptance

The B6-4 live UI probe reported:

```text
checkpoint: B6-4-live-threat-card-ui
state: COMPLETED_FINDINGS
coverage: COMPLETE
findings_count: 7
card_count: 7
threat_section_visible: true
severity_matches_result: true
confidence_matches_result: true
per_card_advanced_available: true
per_card_advanced_payload_present: true
set_result_seen: true
scan_page_horizontal_scroll_max: 0
dashboard_horizontal_scroll_max: 0
no_destructive_authority: true
failures: []
passed: true
```

Terminal probe result:

```text
B6-4 live Threat Cards UI acceptance PASS.
```

Evidence file produced by the live helper:

```text
acceptance-v011-beta6-b64-live-ui.json
```

## Truthfulness checks closed

The live acceptance proves, for this accepted run:

- every returned Smart Scan finding produced exactly one Threat Card (`7 -> 7`);
- displayed canonical severity matched the source result;
- confidence presentation matched the canonical result and was not synthesized when unavailable;
- per-card Advanced details were available and carried the live evidence payload;
- the threat section was visible after the real scan result was rendered;
- Dashboard and Smart Scan surfaces had no horizontal overflow in the probe;
- no automatic quarantine, repair or destructive action was introduced.

The run contained heuristic/static findings, including historical BC Sentinel test fixtures. A finding is not automatically equivalent to a definitive malware verdict. B6-4 correctly remains a review/explanation milestone rather than a remediation milestone.

## Safety / scope statement

B6-4 adds presentation and evidence drill-down only. It does **not** authorize:

- automatic quarantine;
- deletion;
- process termination;
- repair;
- trust/allowlist mutation;
- registry or boot mutation;
- unlock or write-mount operations;
- format/reimage execution.

Guided response authority belongs to B6-5 and must be separately gated.

## Promotion decision

**LIVE WINDOWS ACCEPTANCE: PASS.**

B6-4 is eligible for the final Windows deterministic stabilization run. Checkpoint/stable refs may be created only after that final branch-head CI is green.

Recommended reasoning for promotion work: **High**. Use **Extra High** for any change to severity/confidence semantics or remediation authority.
