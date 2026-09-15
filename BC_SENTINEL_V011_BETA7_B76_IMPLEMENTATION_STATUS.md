# BC Sentinel v0.11.0-beta.7 — B7-6 Coverage Expansion Campaign

Status: IMPLEMENTED / PENDING WINDOWS ACCEPTANCE

Source checkpoint:
`checkpoint/v011-beta7-b75-pass`
`40f1e9985905ceccc070e8f73d09308a8406d059`

## Purpose

B7-6 measures the six accepted B7-0 scenario families without inventing detector coverage. The campaign is deliberately conservative: accepted B7-4 synthetic chain evidence can justify `PARTIAL` only, while families without accepted scenario-specific evidence become explicit `GAP` entries.

## Expected campaign result

- PARTIAL: 3
  - `B7-POWERSHELL-001`
  - `B7-PERSISTENCE-001`
  - `B7-C2-DNS-001`
- GAP: 3
  - `B7-RANSOMWARE-001`
  - `B7-DEFENSE-EVASION-001`
  - `B7-CREDENTIAL-001`
- VERIFIED: 0

Synthetic evidence never becomes VERIFIED coverage in this milestone.

## Safety contract

The campaign performs no real attack execution. Process execution, file writes, network I/O, registry mutation, credential access and remediation execution are all hard-false. It adds no execution authority and does not alter the accepted B7-0 ledger file.

## Acceptance requirements

- protected B2 state unchanged;
- accepted B7-0 through B7-5 foundations unchanged;
- Beta5/Beta6/all accepted Beta7 predecessor tests green;
- six exact scenario families evaluated;
- every PARTIAL result bound to B7-4 synthetic evidence;
- every GAP includes a reason and next engineering step;
- no VERIFIED claims;
- deterministic campaign ID, serialization and SHA-256 digest;
- local Windows acceptance and Windows CI green before checkpoint freeze.
