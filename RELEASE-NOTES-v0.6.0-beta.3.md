# BC Sentinel v0.6.0-beta.3 — Named Pipe Client Identity Resolution Fix

## Status
DEVELOPMENT VERIFIED — native Windows service-live acceptance required.

## Field issue fixed
v0.6.0-beta.2 successfully created the secured Named Pipe and kept the Windows service RUNNING, but the live client received `named-pipe client identity verification failed`.

The transport previously depended exclusively on `ImpersonateNamedPipeClient` + `OpenThreadToken`. On the tested Windows 11 host this did not yield a queryable client token even after the request had been read.

## beta.3 changes
- Preserve named-pipe impersonation as the preferred identity source.
- Add fail-closed fallback to the kernel-reported connected client PID via `GetNamedPipeClientProcessId`.
- Open only `PROCESS_QUERY_LIMITED_INFORMATION` and `TOKEN_QUERY` on that exact client process.
- Derive SID, administrator membership and session ID from the client process token.
- Never trust PID, SID or administrator state supplied in IPC JSON.
- If both identity paths fail, privileged dispatch remains blocked.
- Add `PIPE_REJECT_REMOTE_CLIENTS` to the Named Pipe mode.
- Add Windows acceptance check `protection-client-identity-path`.
- Add regression tests for fallback ordering, fail-closed behavior, remote-client rejection and version consistency.

## Validation
- Automated suite: 211/211 PASS.
- `compileall`: PASS.
- Windows service-live validation: pending.

## Windows pytest note
A previous elevated/non-elevated pytest run can leave `%TEMP%\\pytest-of-<user>\\pytest-current` with ACLs that cause a session-finish `PermissionError`. This is environmental, not a BC Sentinel test assertion failure. For beta.3 acceptance use a dedicated external temp directory with `--basetemp` rather than placing pytest temp data inside the BC Sentinel project tree, because the project tree is intentionally self-protected.
