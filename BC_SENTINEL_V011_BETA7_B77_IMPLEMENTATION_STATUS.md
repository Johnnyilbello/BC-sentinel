# BC Sentinel v0.11.0-beta.7 — B7-7 Windows Acceptance & Freeze

Status: IMPLEMENTED / PENDING LOCAL WINDOWS ACCEPTANCE

Source checkpoint:

```text
checkpoint/v011-beta7-b76-pass
1bd66f4f9e55313388e871e26c6a35d55a3dbb20
```

## Purpose

B7-7 is the final Beta7 release gate. It does not add new detection or remediation authority. It verifies that every accepted Beta7 intelligence layer remains reproducible, that coverage claims stay conservative, that the harmless attack-chain fixtures remain safe, that the accepted Beta6 portable contract is unchanged, and that the synthetic pipeline's resource cost is explicitly measured.

## Final acceptance contract

B7-7 requires:

- complete Beta5 + Beta6 + Beta7 deterministic regression green;
- B7-0 ledger valid with no unsupported positive claims;
- B7-1 Security Graph deterministic and round-trip stable;
- B7-2 Incident Correlation deterministic and conservative;
- B7-3 Confidence Gate outcomes preserved with no authority grant;
- B7-4 attack-chain fixture safe, synthetic and non-executing;
- B7-5 explanations evidence-bound with no confidence amplification;
- B7-6 campaign exactly `PARTIAL=3`, `GAP=3`, `VERIFIED=0`;
- accepted Beta6 portable GUI contract remains `onedir`, windowed, portable and explicit-operator-action only;
- protected B2 state unchanged from the accepted Beta6 checkpoint;
- resource cost measured for the synthetic final acceptance pipeline;
- no automatic quarantine, repair, restore, DELETE, REPAIR, process termination, trust mutation or privileged-system mutation.

## Resource measurement

`sentinel.beta7_final_acceptance` measures:

- elapsed wall-clock time for the synthetic final acceptance composition;
- peak Python traced memory for the same composition.

The gate uses deliberately generous regression ceilings (`60s`, `512 MiB`) so the measurement catches pathological regressions without converting ordinary CI variance into false failures. Resource values are not included in the deterministic core digest.

## Local acceptance

Run:

```powershell
git fetch origin; git checkout feature/v011-beta7-b77-final-acceptance; git pull --ff-only origin feature/v011-beta7-b77-final-acceptance; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B77.ps1" -ConfirmBeta7FinalAcceptance
```

Expected final line:

```text
BC SENTINEL v0.11.0-beta.7 B7-7 WINDOWS ACCEPTANCE & FREEZE - PASS
```

## Freeze rule

Do not create or move the final Beta7 checkpoint until both the exact-head Windows CI and local Windows acceptance pass. After acceptance, freeze the exact tested code SHA as `checkpoint/v011-beta7-b77-pass`.
