# BC Sentinel — Development Status

## Current line

**v0.10.0-beta.1 — Web Deception & Anti-Scam Foundation**

Status: **LOCAL BASELINE ACCEPTED / READY FOR NATIVE WINDOWS VALIDATION**.

Frozen baseline: **v0.9.0-rc.1 NATIVE WINDOWS ACCEPTED** with 482/482 Python tests and foundation/build/upgrade/live/repair/hardening/post-reboot acceptance passing on the target Windows machine.

BC Sentinel is not production-ready and should not replace Microsoft Defender or the native Windows security stack during development testing.

## v0.10.0-beta.1 scope

The first v0.10 milestone matures the existing Web Protection architecture without HTTPS interception. It adds explainable URL/domain deception evidence and bounded anti-scam lure context while preserving deterministic signed-IOC precedence and exact local domain trust.

Safety invariants:

- heuristic-only score hard cap: 49;
- heuristic-only HIGH qualification: disabled;
- heuristic auto-block: disabled;
- HTTPS MITM/root CA/TLS proxy: disabled;
- lure vocabulary does not score without independent structural risk;
- signed IOC evidence remains authoritative;
- v0.9 RC1 acceptance remains a frozen regression requirement.

## Local verification

- pytest: **491 passed, 1 Windows-only skipped**;
- `compileall`: **PASS**;
- `tools.v010_web_deception_acceptance`: **PASS**;
- frozen `tools.v090_release_candidate_acceptance`: **PASS**;
- exact packaged ZIP re-test: **PASS**;
- aggregate v0.10 Windows foundation probe logic: **PASS** in the non-Windows development environment; full native Windows execution remains required.

## Next release gate

Run the v0.10 foundation/build/upgrade/live/repair/hardening/post-reboot matrix on the target Windows system. Do not merge/freeze Beta1 if a critical v0.9 regression or v0.10 web-deception gate fails.
