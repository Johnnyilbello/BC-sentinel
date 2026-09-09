# BC Sentinel v0.11.0-beta.1 — Windows live regression status

Date: 2026-09-09

Latest FULL-tree Windows run:
- service-update compatibility migration installed;
- 573/573 pytest PASS;
- EDR local acceptance PASS;
- build and named-pipe self-test PASS;
- admin phase advanced beyond upgrade/repair;
- current blocker: legacy Web Protection live regression after repair.

Diagnosis:
- the legacy live gate is stricter than the preceding v0.10 live regressions because it requires live DNS ETW tracking (`dns_etw=true`);
- after service repair/restart, ETW previously attempted the DNS provider only once before degrading to base process/file ETW;
- this can create a startup race while still leaving the service otherwise responsive.

Fix on branch:
- bounded DNS ETW provider startup retry: 4 attempts with short bounded backoff before degraded fallback;
- fresh ProviderInfo objects per retry;
- post-repair service readiness gate that requires active reversible mode, `dns_etw=true`, PID-scoped DNS, shared-IP guard, no HTTPS MITM, and no auto-block;
- granular live-regression stage names;
- legacy Web acceptance failure now serializes the full live result/service status into the admin result instead of returning a generic label;
- readiness remains fail-closed: waiting/retry never converts `dns_etw=false` into PASS.

Remaining native acceptance:
- rerun one-command Windows orchestration;
- require service readiness PASS;
- require all live regressions PASS;
- require Windows acceptance PASS;
- require service-performance thresholds, especially idle CPU <=25% of one core;
- reboot remains deferred to final-roadmap validation.
