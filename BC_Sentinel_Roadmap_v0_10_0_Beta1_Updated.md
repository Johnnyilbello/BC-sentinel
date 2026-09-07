# BC Sentinel Roadmap — v0.10.0-beta.1

Current line: **v0.10.0-beta.1 — Web Deception & Anti-Scam Foundation**.

Frozen baseline: **v0.9.0-rc.1 — NATIVE WINDOWS ACCEPTED**.

## Beta1 scope

- mixed-script/IDN hostname deception evidence;
- URL userinfo/raw-IP/obfuscation/redirect context;
- bounded scam-lure context requiring independent structural risk;
- explicit evidence families, signal codes and provenance;
- heuristic score cap 49;
- no heuristic HIGH/auto-block/destructive response;
- signed IOC precedence and exact trust preserved;
- no HTTPS MITM.

## Beta1 exit criteria

- full Python regression green with the frozen v0.9 RC1 gate;
- dedicated v0.10 local acceptance passes;
- native Windows foundation gate passes;
- protected upgrade from v0.9.0-rc.1 succeeds;
- live Protection Service exposes the v0.10 deception profile;
- live safe/risky URL fixtures preserve the same scoring and no-auto-block policy;
- repair and post-reboot regression remain green.
