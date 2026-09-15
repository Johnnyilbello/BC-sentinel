# BC Sentinel v0.11.0-beta.7 — B7-4 Local Windows Acceptance

## Accepted milestone

B7-4 — Attack-Chain Acceptance Harness

Branch tested:

```text
feature/v011-beta7-b74-attack-chain-harness
```

Accepted commit:

```text
d836aef24480d21e6631c1fe0dac640c7862e7ec
```

Frozen predecessor:

```text
checkpoint/v011-beta7-b73-pass
eef5c40edc853ff3f13cb521ce980dcaaea75fd0
```

Final checkpoint created after local + CI acceptance:

```text
checkpoint/v011-beta7-b74-pass
```

## Local Windows result

```text
394 passed, 36 warnings
Compile gate: PASS
Predecessor + B7-4 deterministic gate: PASS
B7-0 coverage ledger self-check: PASS
B7-1 Security Graph self-check: PASS
B7-2 Incident Correlation self-check: PASS
B7-3 Confidence Gate self-check: PASS
Attack-Chain determinism + harmlessness + safety contract: PASS
BC SENTINEL v0.11.0-beta.7 B7-4 ATTACK-CHAIN ACCEPTANCE HARNESS - PASS
```

## Controlled attack-chain evidence

Scenario:

```text
b74-controlled-script-persistence-dns-chain
```

Accepted stage order:

```text
PROCESS -> SCRIPT -> PERSISTENCE -> DNS -> DETECTION
```

Observed acceptance values:

```text
stage_count: 5
graph_edge_count: 4
correlation_link_count: 17
detection_latency: 4.0
report_digest: f61c2824573727942301d021f0c223b9c6accbd863c120aefe237462726a16c6
```

Confidence Gate end-to-end outcomes:

```text
b74-case-recommend = RECOMMEND
b74-case-review = REVIEW_REQUIRED
b74-case-blocked = BLOCKED_INSUFFICIENT_EVIDENCE
```

`advisory_interruption_eligible = true` was accepted only as an advisory eligibility result. `authority_granted = false` remains mandatory.

## Safety invariants

The accepted local run confirmed:

```text
synthetic_fixture_only = true
process_execution = false
file_write = false
network_io = false
registry_mutation = false
remediation_execution = false
automatic_quarantine = false
automatic_repair = false
automatic_restore = false
general_home_execution_authorized = false
DELETE = false
REPAIR = false
TERMINATE_PROCESS = false
TRUST/ALLOWLIST mutation = false
authority_granted = false
execution_authority_added = false
```

The source Security Graph and Incident Correlation outputs remained unchanged. Stable round-trip and deterministic serialization passed.

## Predecessor integrity

- Protected B2 state unchanged from accepted Beta6: PASS.
- Accepted B7-0/B7-1/B7-2/B7-3 foundations unchanged: PASS.
- Beta5 + Beta6 + all accepted Beta7 predecessor regressions: PASS.

## CI

Windows CI for commit `d836aef24480d21e6631c1fe0dac640c7862e7ec` completed successfully, including compile, deterministic regression, all predecessor self-checks, B7-4 self-check and safety assertions.

## Verdict

**B7-4 CLOSED / ACCEPTED.**

The attack-chain harness is accepted as a deterministic, harmless, read-only synthetic acceptance layer. It does not grant or expand remediation authority.
