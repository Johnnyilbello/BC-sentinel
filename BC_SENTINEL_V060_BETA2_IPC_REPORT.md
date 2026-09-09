# BC Sentinel v0.6.0-beta.2 — IPC Authentication Ordering Report

## Field evidence
v0.6.0-beta.1 successfully built a frozen Protection Service, passed named-pipe self-test, installed as `BCSentinelProtection`, remained `RUNNING`, and passed `protection-pipe-create`. The live client failed at `ReadFile` with Win32 error 233 because the server side disconnected before returning a response.

## Root cause
`WindowsNamedPipeServer._handle_client()` called `client_context_from_pipe()` before `_read_message()`. The former invokes `ImpersonateNamedPipeClient()`. Windows derives the impersonated security context from the last message read from the named pipe. Because no message had yet been read by the server thread, impersonation could fail. That exception occurred before the handler's dispatch/response block, causing disconnect without a response.

## Security-preserving fix
The request is now read first under a strict maximum message size. No request is dispatched at that stage. The server then impersonates the client and derives SID/admin context. Only after successful identity establishment does authorization and command dispatch run. If impersonation fails, dispatch is skipped and the request fails closed.

This does not weaken the authorization model: installation token verification, local-only transport, pipe ACLs, authenticated identity, and administrator gating remain in force.

## Validation
- 207 automated tests PASS.
- Added source-order invariants.
- Added behavioral handler test proving `read -> impersonate -> dispatch -> write`.
- Python compileall PASS.

## Native Windows freeze gate
Run a 200-file `--service-live` acceptance first. Expected critical checks include `protection-pipe-create=pass`, `protection-service-live=pass`, and an empty `critical_failures` array. If green, rerun the 5000-file final acceptance.
