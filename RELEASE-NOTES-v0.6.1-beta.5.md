# BC Sentinel v0.6.1-beta.5 — ACL Posture Trusted-Writer Fix

## Fixed

- Fixed `NameError: TRUSTED_WRITE_SIDS is not defined` in the live ACL posture inspection path.
- Defines the trusted writer set narrowly as LocalSystem (`S-1-5-18`) and BUILTIN\Administrators (`S-1-5-32-544`).
- Preserves the existing explicit trust path for Windows service SIDs (`S-1-5-80-*`).
- Does not trust Users, Authenticated Users or Everyone for protected-tree write/control access.
- Extends Windows acceptance so the hardening foundation fails if the trusted-writer constant is missing again.

## Preserved

- Program Files deployment and ProgramData ACL recovery.
- Authenticated integrity manifest and Windows ChangeTime timestamp-evasion protection.
- Named Pipe identity authentication and transient-listener resilience.
- SCM posture checks and HMAC chained audit.

## Validation

- Development regression suite: 242/242 PASS.
- `compileall`: PASS.
- Native Windows `protection-hardening-live` remains pending until user acceptance.
