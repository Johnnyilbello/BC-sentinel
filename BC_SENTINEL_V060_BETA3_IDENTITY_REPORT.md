# BC Sentinel v0.6.0-beta.3 — IPC Client Identity Report

## Field evidence
The beta.2 Windows run proved:
- frozen Protection Service build succeeds;
- Named Pipe self-test succeeds;
- SCM service state is RUNNING;
- `protection-pipe-create` passes;
- live service request reaches the server;
- response is `named-pipe client identity verification failed`.

This isolates the remaining blocker to Windows client-token resolution, not service lifecycle, packaging, pipe creation, protocol parsing, or detection engines.

## Root cause addressed
The server used only `ImpersonateNamedPipeClient` followed by `OpenThreadToken`. This is the preferred path, but on the tested host it did not provide a queryable token. beta.3 keeps that path and adds a second kernel-derived identity source.

## Identity algorithm
1. Read bounded request.
2. Attempt Named Pipe impersonation and query the thread token.
3. If unavailable, call `GetNamedPipeClientProcessId` on the connected server-side pipe handle.
4. Open the exact client process with `PROCESS_QUERY_LIMITED_INFORMATION`.
5. Open its token with `TOKEN_QUERY` only.
6. Derive SID, administrator membership and session ID.
7. Authorize protocol token + Windows identity.
8. Dispatch only after identity succeeds.

No PID/SID supplied by request JSON is trusted.

## Local-only hardening
`PIPE_REJECT_REMOTE_CLIENTS` is now set when creating the production Named Pipe in addition to the existing Windows DACL.

## Failure policy
If impersonation and process-token resolution both fail, the request receives a generic transport authentication error and no privileged operation is dispatched.

## Validation
- 211 tests PASS.
- compileall PASS.
- Added tests for process-token fallback and fail-closed dual failure.
- Added acceptance marker `protection-client-identity-path`.

## Required native gate
`protection-service-live` must PASS on the Windows host before v0.6 is frozen.
