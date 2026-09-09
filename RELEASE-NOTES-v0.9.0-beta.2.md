# BC Sentinel v0.9.0-beta.2

## Reversible Persistence Remediation & PUP/Adware Response

This development release adds the first reversible antispyware response layer on top of the v0.9 Beta1 persistence inventory.

### New

- HMAC-SHA256 authenticated remediation plans bound to stable `BCP-*` findings.
- Explicit plan/apply/restore lifecycle with persisted provenance and status.
- Exact object snapshot and anti-race verification before any system mutation.
- Reversible Registry value disable/restore for Run, RunOnce and selected browser policies.
- Startup-folder file vaulting/restoration with SHA-256 and reparse-point protection.
- Scheduled Task disable/enable support.
- Automatic-service persistence response by changing only startup type from Automatic to Manual; the running service is not terminated.
- Loaded interactive-user `HKEY_USERS` Run/RunOnce discovery from the LocalSystem Protection Service context.
- PUP/adware candidate classification for non-standard forced browser extensions and bounded browser/search helper patterns.
- New read-only remediation-plan IPC surface and privileged apply/restore operations compatible with the existing one-action UAC broker.
- New critical Windows acceptance gates: `antispyware-v090-beta2-foundation` and `antispyware-v090-beta2-live`.

### Safety invariants

- `automatic_remediation = false`
- `automatic_destructive_action = false`
- explicit operator approval is mandatory for apply and restore
- plan integrity is authenticated with HMAC-SHA256
- system state is re-checked before mutation; changed objects fail closed
- WMI subscriptions, DNS and proxy configuration remain review-only in Beta2
- antispyware remediation never terminates a service process
- PUP/adware evidence alone does not become a destructive malware verdict

### Compatibility

All v0.8 threat-intelligence/update-channel controls and v0.9 Beta1 detection-first safety rules remain required regression gates.
