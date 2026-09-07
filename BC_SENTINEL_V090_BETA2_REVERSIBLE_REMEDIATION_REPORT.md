# BC Sentinel v0.9.0-beta.2 — Reversible Remediation Report

## Goal

Introduce a persistence-response layer without converting antispyware heuristics into destructive automatic enforcement.

## Architecture

A suspicious antispyware finding can produce a `BCR-*` remediation plan. The plan stores an exact object snapshot and a machine-keyed HMAC. Apply/restore are separate privileged operations and require explicit approval.

Supported reversible surfaces in Beta2:

- registry Run/RunOnce;
- selected browser-policy registry values;
- Startup files through a managed vault;
- Scheduled Task enabled state;
- automatic-service start mode.

Review-only surfaces:

- WMI subscriptions;
- proxy configuration;
- DNS configuration.

## Fail-closed behavior

Mutation is rejected if the protected object changed after the plan was created. Restore is rejected if the original destination/value has been occupied by different data. Plan HMAC failure blocks execution.

The remediation layer never terminates a service process and does not provide a generic privileged shell.

## PUP/adware

PUP/adware indicators are bounded advisory signals. They can recommend a reversible plan but cannot independently qualify a destructive malware verdict.

## Verification

Final extracted package:

```text
469 passed, 1 Windows-only skipped
compileall PASS
10/10 local acceptance suites PASS
```

Native Windows freeze remains pending.
