# BC Sentinel Roadmap — v0.9.0-rc.1

Current line: **v0.9.0-rc.1 — Antimalware Consolidation & Native Hardening**.

- v0.9.0-beta.1: Antispyware & persistence detection foundation.
- v0.9.0-beta.2: Reversible persistence remediation & PUP/Adware response.
- v0.9.0-beta.3: Advanced antimalware, PowerShell/script/LOLBin and fileless correlation.
- v0.9.0-rc.1: regression freeze, false-positive hardening, native Windows aggregate acceptance and live-service release gate.

## Exit criteria for v0.9

- full Python regression suite green;
- all cross-platform v0.8/v0.9 acceptance gates green;
- benign dual-use/admin matrix stays below HIGH while strong malicious chains remain detectable;
- native Windows aggregate acceptance passes with zero critical failures;
- live Protection Service acceptance passes, including antispyware, remediation and advanced-antimalware surfaces;
- upgrade/repair and reboot-persistence acceptance remain green on the protected Windows installation.

After v0.9 is frozen, the roadmap proceeds to **v0.10 — Web Protection, Anti-Phishing & Anti-Truffa mature expansion**, followed by EDR, sandbox, IDS/IPS, privacy and identity modules.
