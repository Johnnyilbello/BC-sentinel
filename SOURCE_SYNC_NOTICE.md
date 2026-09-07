# Source synchronization status

This branch advances BC Sentinel to `v0.10.0-beta.1 — Web Deception & Anti-Scam Foundation` while preserving `v0.9.0-rc.1` as the frozen native-Windows regression baseline.

## Candidate source delta

The v0.10 Beta1 delta adds explainable Web Protection deception/scam evidence, a dedicated acceptance harness, regression tests, aggregate Windows acceptance hooks and updated release/version documentation.

Core safety boundaries remain unchanged: no HTTPS MITM, no injected root CA/TLS proxy, no heuristic-only HIGH qualification or automatic blocking, and signed IOC precedence remains authoritative.

The connected GitHub integration tracks the navigable security-relevant delta and release evidence; it does not claim that every file from the complete candidate archive has been materialized individually in the repository.

## Complete source-of-record

`BC_Sentinel_v0_10_0_Beta1_Web_Deception_Anti_Scam_Foundation.zip`

SHA-256:

`82e82ae4cfd7fe0b075d35fd4f7fe1e7b7d67e9707cb92b7cc6fe3675c34b8f0`

The exact packaged archive was re-extracted and verified with **491 passed, 1 Windows-only skipped**, `compileall` PASS and the dedicated v0.10 acceptance PASS. The frozen v0.9 RC1 regression gate also passes.

Generated caches, local virtual environments and local acceptance JSON outputs are not source-of-record.

Native Windows acceptance is still required before this Beta1 milestone is frozen or merged as an accepted baseline.
