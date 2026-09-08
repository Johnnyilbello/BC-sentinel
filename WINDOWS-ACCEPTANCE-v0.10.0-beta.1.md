# Windows Acceptance — BC Sentinel v0.10.0-beta.1

Release line: **Web Reputation & Phishing Detection Foundation**

Status: **NOT YET RUN ON THE CHECKPOINT-4-REBASED COMPLETE TREE**.

## Required v0.10 gates

### `web-reputation-v010-beta1-foundation`

Must prove, using deterministic/local fixtures:

- APP version is `0.10.0-beta.1`;
- heuristic score cap is 49;
- safe lure words alone remain unscored;
- benign IDN remains below the review threshold by itself;
- mixed-script/confusable look-alike is detected but remains advisory;
- edit-distance-one typosquatting is detected but remains advisory;
- declared identity is kept separate from observed/canonical domain identity;
- redirect look-alike context is detected without automatic containment;
- enterprise false-positive matrix remains below review threshold;
- signed malicious domain IOC remains deterministic;
- exact-domain trust remains exact only;
- active signed IOC overrides older exact-domain trust;
- `mitm_https=false`;
- heuristic auto-block/destructive action are false;
- no mandatory cloud dependency.

### `web-reputation-v010-beta1-live`

When native live validation is intentionally resumed, the running Protection Service must expose and prove:

- `deception_profile=v0.10.0-beta.1`;
- `heuristic_score_cap=49`;
- `heuristic_can_qualify_high=false`;
- `auto_block=false`;
- `mitm_https=false`;
- look-alike/typosquat/scam-lure/redirect capabilities enabled as advisory context;
- `download_origin_never_overrides_file_verdict=true`;
- safe URL assessment stays below review threshold;
- risky mixed-script fixture remains ≤49 and cannot request blocking by heuristic evidence alone.

## Frozen regression requirements reused from v0.7.2

The acceptance run must retain the already established Web Protection invariants:

- PID-scoped DNS→IP→connection attribution;
- exact known-browser process context;
- shared-IP/CDN suppression for unsafe domain→address inference;
- signed IOC precedence;
- exact-domain trust only;
- persistent `BCW-*` findings;
- browser/domain/network→`BCD-*` download provenance;
- independent file verdict;
- downloaded-file execution evidence feeding incident correlation;
- no origin-driven automatic quarantine.

## Deferred v0.9 native debt

The v0.9.0-rc.1 checkpoint-4 elevated current-build/live/UAC/upgrade/repair/reboot gates remain **OPEN / DEFERRED**. v0.10 acceptance must not mark them PASS merely because v0.10 development proceeds.

## Full acceptance order

1. rebase v0.10 delta onto exact checkpoint-4 complete source tree;
2. targeted v0.10 pytest modules;
3. complete regression suite, preserving all 578 existing tests and adding the new tests;
4. compileall;
5. local v0.10 acceptance;
6. fresh Protection Service and UAC Broker builds;
7. artifact integrity;
8. `web-reputation-v010-beta1-foundation`;
9. `web-reputation-v010-beta1-live` only when running the live native service.

No archive/release checksum should be generated before the relevant gates pass.