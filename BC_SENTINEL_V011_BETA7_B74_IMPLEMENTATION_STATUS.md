# BC Sentinel v0.11.0-beta.7 — B7-4 Implementation Status

Status: **IMPLEMENTED — WINDOWS CI + LOCAL DEVICE ACCEPTANCE PENDING**

Active branch:

```text
feature/v011-beta7-b74-attack-chain-harness
```

Accepted predecessor:

```text
B7-3 — Confidence Gate
checkpoint/v011-beta7-b73-pass
eef5c40edc853ff3f13cb521ce980dcaaea75fd0
Windows CI: PASS
Local Windows acceptance: PASS
```

## Scope

B7-4 adds a harmless, deterministic **Attack-Chain Acceptance Harness** over the accepted read-only B7-1/B7-2/B7-3 intelligence stack.

The harness uses only synthetic in-memory fixtures. It does not launch processes, write files, contact networks, mutate registry state, or execute remediation.

## Controlled chain

The primary fixture models this ordered evidence chain:

```text
PROCESS -> SCRIPT -> PERSISTENCE -> DNS -> DETECTION
```

All timestamps are synthetic fixture values. The harness derives observation and detection timing from those values and never uses timing proximity alone as incident evidence.

## End-to-end acceptance

The harness verifies:

- exact five-stage order;
- deterministic Security Graph construction;
- one correlated incident containing the complete controlled chain;
- preserved source graph and correlation digests;
- explicit evidence binding;
- exact synthetic detection latency;
- B7-3 advisory gate outcomes for the same chain:
  - `RECOMMEND` for strong bounded reversible evidence;
  - `REVIEW_REQUIRED` for high potential damage;
  - `BLOCKED_INSUFFICIENT_EVIDENCE` for weak/low-confidence evidence;
- advisory interruption eligibility is true only for `RECOMMEND`;
- eligibility never means execution authority;
- stable JSON serialization, round-trip and SHA-256 report digest;
- tampered stage order, side-effect flags, authority flags and eligibility fail validation.

## Safety boundary

```text
synthetic_fixture_only = true
process_execution      = false
file_write             = false
network_io             = false
registry_mutation      = false
remediation_execution  = false
authority_granted      = false
execution_authority_added = false
```

B7-4 does not alter the accepted detector/remediation authority model.

## Predecessor freeze

Local acceptance verifies that:

- protected B2 state is unchanged from accepted Beta6;
- B7-0 coverage ledger files are unchanged;
- B7-1 Security Graph files are unchanged;
- B7-2 Incident Correlation files are unchanged;
- B7-3 Confidence Gate files are unchanged from `checkpoint/v011-beta7-b73-pass`.

## Automated gate

Windows CI runs:

1. compile B7-0 through B7-4 modules/tests;
2. Beta5 + Beta6 + accepted Beta7 predecessor regression plus B7-4 tests;
3. B7-0 Coverage Ledger self-check;
4. B7-1 Security Graph self-check;
5. B7-2 Incident Correlation self-check;
6. B7-3 Confidence Gate self-check;
7. B7-4 Attack-Chain Harness self-check;
8. explicit no-side-effect/no-authority assertions.

## Local Windows acceptance

Run from normal PowerShell in repository root:

```powershell
git fetch origin; git checkout feature/v011-beta7-b74-attack-chain-harness; git pull --ff-only origin feature/v011-beta7-b74-attack-chain-harness; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B74.ps1" -ConfirmAttackChainAcceptance
```

Expected final line:

```text
BC SENTINEL v0.11.0-beta.7 B7-4 ATTACK-CHAIN ACCEPTANCE HARNESS - PASS
```

Do not create `checkpoint/v011-beta7-b74-pass` until both Windows CI and local-device acceptance pass.
