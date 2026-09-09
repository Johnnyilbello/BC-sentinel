# BC Sentinel v0.9.0-beta.1 — Antispyware & Advanced Antimalware Foundation

BC Sentinel v0.9 opens the antispyware/advanced-antimalware development line while preserving the native-Windows-accepted v0.8 threat-intelligence and release-hardening foundation.

## New in Beta1

- read-only Windows persistence inventory covering Run/RunOnce, Startup folders, Scheduled Tasks, automatic services, WMI permanent command consumers, browser policy roots, proxy configuration and DNS configuration;
- persistent `BCP-*` antispyware findings with exact source/location/name/command/target provenance;
- conservative multi-signal persistence scoring with Authenticode context, missing-target detection, user-writable/high-risk path context, interpreter/encoded-command signals and browser/network-configuration context;
- signed/legitimate persistence can remain SAFE/LOW; a persistence signal by itself is never classified as malware;
- persistence-only heuristic scoring is capped below HIGH; HIGH/CRITICAL requires stronger independent evidence such as a qualified file verdict;
- antispyware findings feed the existing Behavioral Correlation and Incident Engine pipeline;
- read-only Protection Service APIs for antispyware status and findings;
- UI protection-center capability card;
- new Windows acceptance gates `antispyware-v090-beta1-foundation` and `antispyware-v090-beta1-live`.

## Safety policy

This Beta is detection-first. It does **not** automatically delete Registry values, Scheduled Tasks, services, WMI subscriptions or browser/network configuration.

The remediation contract is intentionally limited to review and future reversible remediation plans. Existing file quarantine/delete paths remain governed by qualified HIGH/CRITICAL file verdicts and the Threat Decision Center.

## Not yet in Beta1

- automatic or transactional persistence disable/restore;
- deep credential-stealer memory/browser-secret hunting;
- AMSI/PowerShell content inspection;
- full LOLBin/fileless behavioral policy expansion;
- automatic PUP/adware removal.

These are planned for later v0.9 betas after the detection baseline earns native Windows acceptance.
