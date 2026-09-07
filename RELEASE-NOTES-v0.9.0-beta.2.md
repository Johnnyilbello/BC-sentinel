# BC Sentinel v0.9.0-beta.2

## Reversible Persistence Remediation & PUP/Adware Response

Beta2 extends the v0.9 antispyware foundation with explicit, reversible persistence response.

### Added

- HMAC-SHA256 authenticated remediation plans (`BCR-*`);
- explicit approval requirement for apply and restore;
- exact snapshot verification immediately before mutation;
- reversible Run/RunOnce and selected browser-policy registry handling;
- Startup-item managed vault with SHA-256 verification and restore;
- Scheduled Task disable/enable restoration;
- automatic-service start-mode remediation without terminating the service process;
- protected service/UAC operations for remediation apply/restore;
- persistent remediation-plan history and summary;
- bounded PUP/adware candidate classification;
- interactive-user `HKEY_USERS` Run/RunOnce discovery for LocalSystem service context;
- dedicated Beta2 acceptance harness and Windows aggregate gates.

### Safety

- `automatic_remediation=false`;
- `automatic_destructive_action=false`;
- `service_process_termination=false`;
- WMI persistence remains review-only;
- proxy and DNS configuration remain review-only;
- plan tampering is rejected;
- object changes after planning cause fail-closed conflict rejection;
- restoration refuses to overwrite a conflicting new value/file state.

### Verification

Extracted release-tree result:

```text
469 passed, 1 Windows-only skipped
compileall PASS
10/10 local acceptance suites PASS
```

Native Windows acceptance is required before this Beta is frozen.
