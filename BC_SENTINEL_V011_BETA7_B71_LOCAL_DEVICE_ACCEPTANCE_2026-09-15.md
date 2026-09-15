# BC Sentinel v0.11.0-beta.7 — B7-1 Local Windows Acceptance

Date: 2026-09-15

Milestone: **B7-1 — Sentinel Security Graph Foundation**

Accepted commit:

```text
c75697b25c63e59bdfc2ad32374c4232c607fea0
```

Accepted checkpoint:

```text
checkpoint/v011-beta7-b71-pass
```

## Local Windows acceptance

Command executed from normal PowerShell on the Windows development machine:

```powershell
git fetch origin; git checkout feature/v011-beta7-b71-security-graph; git pull --ff-only origin feature/v011-beta7-b71-security-graph; powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\TEST-V011-BETA7-B71.ps1" -ConfirmSecurityGraphAcceptance
```

Result: **PASS**

Key evidence:

- protected B2 state unchanged from accepted Beta6: PASS;
- accepted B7-0 ledger foundation unchanged: PASS;
- compile gate: PASS;
- Beta5 + Beta6 + B7-0 predecessor regression + B7-1 deterministic tests: **361 passed, 36 warnings**;
- B7-0 coverage ledger self-check: PASS;
- B7-1 Security Graph semantic/determinism self-check: PASS;
- graph schema: `bc-sentinel-security-graph-v1`;
- profile: `v0.11.0-beta.7-b71-security-graph`;
- deterministic serialization: true;
- stable round trip: true;
- provenance required: true;
- edge reason required: true;
- conflicting duplicate IDs allowed: false;
- missing-node edges allowed: false;
- graph digest: `10380636f532f5aaf477fd9d179214c212955e9088c87e0c219d655b09eac775`.

## Safety boundary verified

```text
read_only = true
execution_authority_added = false
automatic_quarantine = false
automatic_repair = false
automatic_restore = false
general_home_execution_authorized = false
DELETE = false
REPAIR = false
TERMINATE_PROCESS = false
TRUST/ALLOWLIST mutation = false
```

Final local gate line:

```text
BC SENTINEL v0.11.0-beta.7 B7-1 SENTINEL SECURITY GRAPH FOUNDATION - PASS
```

## Windows CI

GitHub Actions workflow: `B7-1 Security Graph Gate`

Run ID: `34974953956`

Head SHA: `c75697b25c63e59bdfc2ad32374c4232c607fea0`

Conclusion: **SUCCESS**

The CI run completed successfully on the same commit accepted locally.