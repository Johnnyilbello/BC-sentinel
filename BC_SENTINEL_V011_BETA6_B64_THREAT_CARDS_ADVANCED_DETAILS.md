# BC Sentinel v0.11.0-beta.6 — B6-4 Threat Cards + Advanced Details

Status: **OPEN / IMPLEMENTATION STARTED**

Primary branch: `feature/v011-beta6-b64-threat-cards`

Parent stable checkpoint:

```text
B6-3 Smart Scan
f9fab1768d6a4c185ff3a83f01e4a6ed90aaf81c
```

## Goal

Turn accepted Smart Scan findings into understandable, truthful threat-review cards without changing scanner verdicts, severity, confidence, evidence, or remediation authority.

B6-4 is a **presentation and evidence-access milestone**. It does not add automatic quarantine, deletion, process termination, repair, registry/boot writes, unlock, write mounts, format, reimage, or any other destructive authority.

## Product contract

BC Sentinel continues to expose one Home experience with two information levels, not separate user/expert modes:

1. **Default threat card** — concise explanation for a normal user.
2. **Advanced details** — complete technical evidence and provenance for expert review.

A card must answer, in plain language:

- what was detected;
- how serious the provider classified it;
- why it was surfaced;
- where it was observed when a path/process/indicator is available;
- confidence when the provider supplied confidence;
- what the user should do next without pretending remediation has already occurred.

Advanced details must preserve the accepted source evidence, including the original finding payload, source check result, provider identity/provenance, scan/session context, coverage state, and raw provider evidence relevant to the result.

## Truthfulness rules

B6-4 MUST NOT:

- upgrade or downgrade severity;
- synthesize confidence when none exists;
- convert heuristic/suspicious evidence into a definitive malware claim;
- hide incomplete/cancelled scan state;
- call a finding `malware`, `virus`, `trojan`, or similar unless the provider evidence actually supplies that meaning;
- claim an action was taken when none was taken;
- imply whole-disk cleanliness from bounded Smart Scan scope;
- suppress source evidence from Advanced details.

If a provider omits optional user-facing fields, the presentation layer may state only that the information is unavailable; it must not invent substitute evidence.

## Severity presentation

The canonical Smart Scan severities remain authoritative:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

B6-4 may localize labels and apply visual roles, but the canonical severity value must remain visible in Advanced details.

Suggested visual roles:

```text
INFO      -> neutral
LOW       -> attention
MEDIUM    -> attention
HIGH      -> danger
CRITICAL  -> danger
```

These roles are presentation-only and must not alter scan semantics.

## Confidence presentation

When `finding.confidence` is present, display the exact bounded value as a percentage rounded only for display. Preserve the original floating-point value in Advanced details.

When confidence is absent, show `Non disponibile`; do not infer confidence from severity, score, signal count, YARA matches, or any other evidence.

## Card ordering

Initial B6-4 preserves provider/result finding order. No ranking engine is introduced in this milestone.

Future ranking may be added only with an explicit contract proving that display ordering cannot mutate severity or evidence semantics.

## Advanced details payload

Each threat card must make available at least:

```text
schema/profile
session_id
correlation_id
scan_state
coverage
provider_name
provider_profile
provider_provenance
finding (exact SmartScanFinding.to_dict())
source_check_result (exact matching SmartScanCheckResult.to_dict(), when present)
scan_raw_evidence
```

The user-facing card may remain concise; Advanced details are the evidence escape hatch.

## Findings preserved after cancellation/incomplete scans

If a cancelled or incomplete Smart Scan produced accepted findings before termination, B6-4 should still render those findings while clearly preserving the parent scan state and incomplete coverage.

A finding card never turns an incomplete scan into a complete scan.

## Actions

B6-4 is review-only.

Allowed actions:

- expand/collapse Advanced details;
- inspect evidence;
- copy/read technical data through existing UI affordances when available.

Forbidden in B6-4:

- one-click quarantine;
- delete;
- kill process;
- repair;
- trust/allowlist mutations;
- registry/boot changes;
- automatic action based only on card severity/confidence.

Guided resolution belongs to B6-5.

## UI requirements

Threat cards must:

- reuse the accepted dark Dashboard visual system;
- avoid horizontal overflow on supported responsive widths;
- wrap path/reason text safely;
- expose an accessible `Dettagli avanzati` control per card;
- avoid danger styling for decorative purposes;
- keep scan-level Advanced details available in addition to per-card evidence;
- preserve the existing Smart Scan progress/cancellation behavior.

## Acceptance gate

B6-4 cannot be promoted until all are true:

1. deterministic mapping tests prove no severity/confidence mutation;
2. missing confidence remains explicitly unavailable;
3. Advanced details preserve exact original finding evidence and provider provenance;
4. cancelled/incomplete scans can show already-produced findings without false complete/clean claims;
5. no remediation authority is introduced;
6. B6-0/B6-1/B6-2/B6-3 predecessor tests remain green;
7. Windows Qt smoke confirms the B6-4 Home renders threat cards without horizontal overflow;
8. a controlled live Smart Scan finding is visibly rendered as a B6-4 threat card on Windows;
9. final Windows CI is green on the promotion commit.

## Reasoning level

Recommended Codex reasoning for implementation: **High**.

Use **Extra High** only if changing severity/confidence truth rules, finding classification, or action-authority boundaries.
