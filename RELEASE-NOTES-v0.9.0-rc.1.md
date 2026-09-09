# BC Sentinel v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening

Release candidate. Not production-ready until the native Windows and live-service acceptance gates pass on the target machine.

## Consolidation scope

- freezes the v0.9 Beta1 antispyware discovery and provenance model;
- freezes the v0.9 Beta2 reversible persistence-remediation and PUP/adware safety boundaries;
- freezes the v0.9 Beta3 PowerShell/script/LOLBin and fileless correlation model;
- adds a dedicated v0.9 release-candidate acceptance gate;
- adds a benign dual-use/admin false-positive matrix that must remain below HIGH;
- verifies that strong multi-signal and deterministic chains still qualify HIGH/CRITICAL;
- preserves advisory-only advanced antimalware behavior: no automatic kill, delete or quarantine;
- preserves explicit-approval-only persistence remediation;
- requires native Windows aggregate acceptance and live Protection Service acceptance before release freeze.

## False-positive hardening gate

The RC explicitly exercises harmless or legitimate-looking PowerShell, CertUtil, MSIExec, BITSAdmin and browser/Office-to-PowerShell scenarios. Routine administrative cases must remain SAFE and every benign matrix case must stay below HIGH. This gate does not create allowlists for dual-use binaries and therefore does not suppress converging malicious evidence.

## Release freeze policy

`0.9.0-rc.1` is considered locally ready only when all v0.8 frozen gates plus v0.9 Beta1, Beta2 and Beta3 regressions remain green. Final freeze additionally requires the target Windows acceptance harness and the already-installed Protection Service live gates to pass with zero critical failures.
