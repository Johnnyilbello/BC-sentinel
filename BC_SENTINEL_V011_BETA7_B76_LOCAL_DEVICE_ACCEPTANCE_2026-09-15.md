# BC Sentinel v0.11.0-beta.7 — B7-6 Local Windows Acceptance

Date: 2026-09-15

## Accepted target

- Branch: `feature/v011-beta7-b76-coverage-expansion`
- Accepted code commit: `1bd66f4f9e55313388e871e26c6a35d55a3dbb20`
- Frozen predecessor: `checkpoint/v011-beta7-b75-pass`
- Predecessor commit: `40f1e9985905ceccc070e8f73d09308a8406d059`
- Frozen checkpoint created after acceptance: `checkpoint/v011-beta7-b76-pass`

## Local Windows acceptance

Command:

```powershell
git fetch origin; git checkout feature/v011-beta7-b76-coverage-expansion; git pull --ff-only origin feature/v011-beta7-b76-coverage-expansion; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B76.ps1" -ConfirmCoverageExpansionAcceptance
```

Result:

```text
413 passed, 36 warnings
Compile gate: PASS
Predecessor + B7-6 deterministic gate: PASS
Coverage Expansion evidence/gap/determinism/safety contract: PASS
BC SENTINEL v0.11.0-beta.7 B7-6 COVERAGE EXPANSION CAMPAIGN - PASS
```

## Accepted campaign contract

- Scenario count: 6
- `PARTIAL`: 3
- `GAP`: 3
- `VERIFIED`: 0
- Unsupported VERIFIED claims: forbidden
- Base ledger mutated: false
- Deterministic serialization: true
- Stable round-trip: true
- Synthetic fixture only: true

Accepted partial coverage:
- `B7-POWERSHELL-001`
- `B7-PERSISTENCE-001`
- `B7-C2-DNS-001`

Accepted explicit gaps:
- `B7-RANSOMWARE-001`
- `B7-DEFENSE-EVASION-001`
- `B7-CREDENTIAL-001`

Campaign digest:

```text
e85f96cdfd21f85390c18e1e75387508ce2453c10dfc1af782ede16faad9fc17
```

B7-4 report digest used as evidence:

```text
f61c2824573727942301d021f0c223b9c6accbd863c120aefe237462726a16c6
```

## Safety invariants

All remain false:

- execution authority added
- automatic quarantine
- automatic repair
- automatic restore
- process execution by campaign
- file writes by campaign
- network I/O by campaign
- registry mutation by campaign
- credential access by campaign
- remediation execution

Protected B2 state and accepted B7-0 through B7-5 foundations remained unchanged.

## CI

Windows GitHub Actions run `34982546626` completed successfully on the exact accepted code commit.

## Verdict

**B7-6 LOCAL WINDOWS ACCEPTED / CLOSED.**

The accepted code checkpoint must not be moved. Any documentation-only commits after this point do not redefine the accepted B7-6 code SHA.
