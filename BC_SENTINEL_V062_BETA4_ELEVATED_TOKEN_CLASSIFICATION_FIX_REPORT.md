# BC Sentinel v0.6.2-beta.4 — Elevated Token Classification Fix Report

## Native finding

On Windows, the frozen UAC broker was manually launched from a confirmed elevated PowerShell session. The host token showed:

- Administrator role: True
- BUILTIN\Administrators SID `S-1-5-32-544` enabled
- High mandatory integrity SID `S-1-16-12288`

The broker's own elevation check passed, but the Protection Service returned `admin_required`. This isolated the defect to server-side client token classification.

## Root cause

The service preferred the named-pipe impersonation token and returned its `CheckTokenMembership` result directly. On the tested Windows path that impersonation token under-reported administrator membership, so the already-elevated broker was treated as standard-user.

## Fix

1. Named-pipe impersonation still determines the authenticated peer identity.
2. If that context is non-admin, the service opens the primary token of the exact kernel-reported named-pipe client PID.
3. An admin result from the process token is accepted only if SID/session/PID match the impersonated context.
4. Explicit token-group inspection recognizes BUILTIN\Administrators only when enabled and not deny-only.
5. Any failure or identity mismatch stays non-admin.

## Expected Windows result

The standard-user `tools.broker_acceptance` should now move from:

`issued=1, consumed=0, completed=0 -> broker_timeout`

to:

`issued=1, consumed=1, completed=1 -> passed=true`

with one UAC consent prompt and no change to the idempotent network state used by the acceptance.
