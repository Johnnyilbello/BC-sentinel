# BC Sentinel v0.6.0-beta.2 — Named Pipe Client Authentication Ordering Fix

## Status
DEVELOPMENT FREEZE — 207/207 automated tests PASS. Native Windows service-live acceptance required.

## Field defect fixed
The beta.1 Windows service successfully installed and remained RUNNING, and the secured pipe creation probe passed. The live IPC request still failed client-side with Win32 error 233 (`ERROR_PIPE_NOT_CONNECTED`) while reading the response.

Root cause: the server attempted `ImpersonateNamedPipeClient()` before reading the client's request. Windows named-pipe impersonation uses the security context of the last message read from the pipe. A failed impersonation escaped before a response was built, so the handler disconnected and the client observed error 233.

## Changes
- Read the bounded request before attempting named-pipe client impersonation.
- Impersonate/authenticate only after a client message exists.
- Never dispatch if transport identity verification fails.
- Return a deterministic `transport_auth_error` for identity failures where the pipe is still writable.
- Per-client response/write failure no longer kills the long-running accept loop.
- Added behavioral regression proving order: read -> impersonate -> dispatch -> write.
- Version: `0.6.0-beta.2` / Python package `0.6.0b3`.

## Validation
- pytest: 207/207 PASS
- compileall: PASS
- Remaining freeze gate: native Windows `--service-live` acceptance.
