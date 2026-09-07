# BC Sentinel v0.9.0-beta.3 — Advanced Antimalware & Fileless Correlation

Development preview. Not production-ready.

## Added

- advisory advanced-antimalware engine for PowerShell, script hosts and Windows LOLBins;
- conservative command-line analysis for encoded/dynamic PowerShell and bounded in-memory execution indicators;
- LOLBin coverage for MSHTA, Rundll32, Regsvr32, Certutil, BITSAdmin, MSIExec, WMIC and CMSTP patterns;
- parent/child context for Office/browser/script-host execution chains;
- same-PID temporal correlation across suspicious execution and network activity;
- qualified deterministic file/IOC evidence can strengthen an existing behavioral chain;
- persistent, explainable advanced-antimalware findings;
- read-only Protection Service status/findings surfaces;
- native Windows acceptance gate `antimalware-v090-beta3-*`.

## Safety invariants

- a single PowerShell/script/LOLBin process is not malware by identity;
- one evidence family cannot qualify HIGH on its own;
- dual-use Windows tooling remains allowed unless multiple independent signals converge;
- no automatic process termination, file deletion, quarantine or persistence mutation is introduced by this module;
- existing Threat Decision, quarantine and reversible remediation boundaries remain unchanged.
