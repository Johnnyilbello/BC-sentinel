# BC Sentinel Development Status

## Current

**v0.9.0-beta.2 — Reversible Persistence Remediation & PUP/Adware Response**

Status: **READY FOR NATIVE WINDOWS ACCEPTANCE**.

Development verification on the extracted release tree:

- pytest: 469 passed, 1 Windows-only skipped;
- compileall: PASS;
- 10/10 local acceptance suites: PASS;
- automatic remediation: disabled;
- automatic destructive persistence action: disabled;
- service process termination by remediation: disabled.

Native Windows target: 470 passed and aggregate `critical_failures=[]`.

## Accepted baseline

`v0.8.0-rc.1 — Consolidation & Release Hardening`: **NATIVE WINDOWS ACCEPTED**.

## v0.9 Beta1

Dedicated antispyware Windows service/live acceptance: PASS. Aggregate Windows output was not supplied before moving to Beta2, so Beta1 is not separately recorded here as a fully frozen aggregate release.

## Next

After Beta2 native acceptance: `v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation`.
