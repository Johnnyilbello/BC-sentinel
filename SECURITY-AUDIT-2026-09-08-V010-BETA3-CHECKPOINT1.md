# Security Audit — v0.10.0-beta.3 checkpoint 1

Beta3 adds clone-site and scam/fraud page-context analysis without widening automatic response authority.

## Threat model controls
- declared identity, observed host and page evidence remain separate fields;
- canonical protected domains suppress clone-site claims for their own brands;
- credential/payment form context is structural evidence, not a malware verdict;
- scam vocabulary is scored only when an independent structural/identity anchor exists;
- score is hard-capped below HIGH at 49;
- `block_recommended` is always false for Beta3 page-context heuristics;
- Beta2 signed-IOC-only reversible containment policy remains authoritative;
- no TLS interception, MITM, root CA, injected browser code or required cloud lookup.

## Adversarial/false-positive matrix
Covered cases include canonical Microsoft login, non-canonical Microsoft credential clone, mixed-script PayPal clone + payment pressure, normal e-commerce checkout, remote-support lure on raw IP, investment/crypto lure on raw IP, stable fingerprints and bounded protocol payloads.

## Local evidence
543 passed, 2 Windows-native skipped, 0 failed. All local Beta1/Beta2/Beta3 acceptance harnesses PASS. Windows service-live, upgrade/repair and true standard-user -> UAC are deliberately delegated to the packaged master launchers. Reboot remains deferred to final roadmap closure.
