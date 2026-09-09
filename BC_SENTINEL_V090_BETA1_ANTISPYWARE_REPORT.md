# BC Sentinel v0.9.0-beta.1 Antispyware Foundation Report

## Goal

Introduce a Windows antispyware/persistence-detection layer without weakening the safety boundaries established in v0.7/v0.8.

## Architecture

`Windows persistence/config inventory → conservative assessment → persistent BCP finding → behavioral correlation → incident engine → operator review`

The collector is read-only and bounded. It does not execute discovered commands and it does not remove persistence.

## Coverage

- HKCU/HKLM Run and RunOnce
- user and common Startup folders
- Scheduled Tasks
- automatic Windows services
- WMI `CommandLineEventConsumer` permanent-consumer inventory
- Chrome/Edge/Firefox policy roots
- Internet Settings proxy values
- IPv4 DNS client configuration

## Scoring invariants

- valid Authenticode is trust context, not an allow-everything bypass;
- unsigned/user-writable/temp-path persistence increases risk;
- encoded PowerShell/interpreter persistence adds independent behavioral evidence;
- missing persistence targets are suspicious maintenance/hijack evidence, not malware by themselves;
- persistence heuristics alone are capped below HIGH;
- a qualified deterministic file verdict may raise the correlated incident to HIGH/CRITICAL;
- antispyware itself never performs a destructive action in Beta1.

## Persistence

Findings are stored in SQLite under stable `BCP-*` identifiers with timestamps, kind, location, command, target, existence/user-writable context, signature/signer, score, reasons and evidence provenance.

## Service/API

Read-only operations:
- `antispyware_status`
- `antispyware_findings`

No new privileged deletion/remediation operation is introduced in Beta1.
