# BC Sentinel v0.9.0-beta.2 — Reversible Remediation Report

## Objective

Add a bounded response layer for suspicious persistence without converting heuristic antispyware findings into destructive automatic actions.

## Remediation model

`finding -> authenticated plan -> explicit privileged approval -> exact-state verification -> disable -> verify -> optional restore`

Supported Beta2 mutation surfaces:

- Registry Run / RunOnce values
- selected browser-policy Registry values
- Startup-folder files via managed vault
- Scheduled Tasks via disable/enable
- automatic services via startup-type change only

Review-only surfaces:

- WMI permanent subscriptions
- DNS configuration
- proxy configuration

## Integrity and rollback

Plans store the exact pre-action snapshot and are authenticated using the machine-private BC Sentinel integrity key with HMAC-SHA256. Before apply, the current object must still match the snapshot. Restore refuses to overwrite conflicting replacement state.

Startup files are moved, not deleted, into a managed remediation vault and verified by SHA-256. Reparse-point ancestry is rejected.

## PUP/adware

PUP/adware indicators are treated as advisory evidence. Non-standard forced browser-extension sources and bounded browser-helper/search-home patterns can recommend a reversible plan, but do not create an automatic malware verdict.

## Safety

No automatic remediation, Registry deletion loop, task deletion, service deletion, WMI deletion or service process termination is enabled in this Beta.
