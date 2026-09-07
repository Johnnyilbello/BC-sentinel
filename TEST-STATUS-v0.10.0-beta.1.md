# BC Sentinel v0.10.0-beta.1 — Test Status

## Development baseline

Local validation completed on the exact candidate tree on 2026-09-07:

- Python suite: **491 passed, 1 Windows-only skipped**;
- `compileall` across `app`, `sentinel`, `tools`, `tests`: **PASS**;
- `tools.v010_web_deception_acceptance`: **PASS**;
- frozen `tools.v090_release_candidate_acceptance`: **PASS**;
- v0.10 aggregate Windows foundation probe logic: **PASS** (`profile=v0.10.0-beta.1`, heuristic cap 49, signed-IOC precedence true, HTTPS MITM false).

## Web-deception safety matrix

- ordinary `login`/`invoice` vocabulary without structural risk: observe / no heuristic escalation;
- nested redirect context alone: bounded low signal;
- mixed-script/IDN + structural deception + lure context: detected but hard-capped at **49**;
- raw-IP + lure context: review, no containment;
- signed malicious domain IOC: deterministic **CRITICAL** precedence retained;
- exact trusted domain: trusted only when no stronger signed IOC is active;
- heuristic-only automatic blocking: **disabled**;
- HTTPS MITM / injected root CA / local TLS proxy: **disabled**.

## Native gate still required

This is not yet a native-Windows freeze. Before Beta1 is accepted, run the full Python suite, dedicated v0.10 acceptance, aggregate Windows foundation, build/upgrade, live-service aggregate acceptance, repair/hardening and post-reboot validation on the Windows target.
