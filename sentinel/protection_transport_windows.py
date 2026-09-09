from __future__ import annotations

import os
import threading

from .protection_protocol import ClientContext, MAX_MESSAGE_BYTES, encode_message, response_error
from .protection_constants import PIPE_NAME


class NamedPipeUnavailable(RuntimeError):
    pass


# ConnectNamedPipe can surface per-instance races when a client opens/closes
# before the blocking accept is established. These conditions are recoverable:
# discard that pipe instance and create a fresh one instead of terminating the
# whole protection service. Values are stable Win32 error codes.
TRANSIENT_CONNECT_ERRORS = frozenset({
    109,  # ERROR_BROKEN_PIPE
    232,  # ERROR_NO_DATA
    233,  # ERROR_PIPE_NOT_CONNECTED
    995,  # ERROR_OPERATION_ABORTED
})


def is_transient_connect_error(code: int) -> bool:
    return int(code) in TRANSIENT_CONNECT_ERRORS


def _imports():
    if os.name != "nt":
        raise NamedPipeUnavailable("Windows named pipes are only available on Windows.")
    try:
        import pywintypes
        import win32api
        import win32con
        import win32file
        import win32pipe
        import win32security
    except ImportError as exc:
        raise NamedPipeUnavailable("pywin32 is required for the protection service named pipe.") from exc
    return pywintypes, win32api, win32con, win32file, win32pipe, win32security


def build_pipe_security_attributes():
    _, _, _, _, _, win32security = _imports()
    # LocalSystem/Admin full access. Authenticated local users may connect, but
    # the per-install secret and command authorization policy still apply.
    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        sddl, win32security.SDDL_REVISION_1
    )
    if not sd.IsValid():
        raise NamedPipeUnavailable("Protection pipe security descriptor is invalid.")
    # SECURITY_ATTRIBUTES from win32security is the documented constructor for
    # attaching a PySECURITY_DESCRIPTOR to Win32 object creation calls.
    attrs = win32security.SECURITY_ATTRIBUTES()
    attrs.SECURITY_DESCRIPTOR = sd
    attrs.bInheritHandle = False
    return attrs


def _close_handle_safely(handle) -> None:
    if handle is None:
        return
    try:
        close = getattr(handle, "Close", None)
        if callable(close):
            close()
            return
    except Exception:
        pass
    try:
        _, win32api, _, _, _, _ = _imports()
        win32api.CloseHandle(handle)
    except Exception:
        pass


def _token_has_enabled_admin_group(token) -> bool:
    """Return True only when BUILTIN\\Administrators is enabled in this token.

    Windows UAC filtered tokens can still contain the Administrators SID as
    deny-only.  Treat that as non-admin.  This explicit TokenGroups fallback
    also covers impersonation-token cases where CheckTokenMembership can be
    conservative even though the exact connected process is elevated.
    """
    _, _, _, _, _, win32security = _imports()
    try:
        admin_sid = win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid, None
        )
        admin_text = win32security.ConvertSidToStringSid(admin_sid)
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
        SE_GROUP_ENABLED = 0x00000004
        SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
        for item in groups or ():
            if not isinstance(item, (tuple, list)) or len(item) < 2:
                continue
            group_sid, attrs = item[0], int(item[1])
            try:
                group_text = win32security.ConvertSidToStringSid(group_sid)
            except Exception:
                continue
            if group_text != admin_text:
                continue
            return bool(attrs & SE_GROUP_ENABLED) and not bool(attrs & SE_GROUP_USE_FOR_DENY_ONLY)
    except Exception:
        return False
    return False


def _context_from_token(token, *, transport: str = "windows_named_pipe", process_id: int | None = None) -> ClientContext:
    _, _, _, _, _, win32security = _imports()
    user = win32security.GetTokenInformation(token, win32security.TokenUser)
    sid = user[0] if isinstance(user, tuple) else user
    sid_text = win32security.ConvertSidToStringSid(sid)
    is_admin = False
    session_id = None
    try:
        admin_sid = win32security.CreateWellKnownSid(
            win32security.WinBuiltinAdministratorsSid, None
        )
        is_admin = bool(win32security.CheckTokenMembership(token, admin_sid))
    except Exception:
        is_admin = False
    if not is_admin:
        is_admin = _token_has_enabled_admin_group(token)
    try:
        session_id = int(
            win32security.GetTokenInformation(token, win32security.TokenSessionId)
        )
    except Exception:
        session_id = None
    return ClientContext(
        local=True,
        authenticated=bool(sid_text),
        is_admin=is_admin,
        sid=sid_text,
        session_id=session_id,
        transport=transport,
        process_id=process_id,
    )


def _client_context_via_impersonation(handle) -> ClientContext:
    _, win32api, _, _, win32pipe, win32security = _imports()
    token = None
    try:
        win32pipe.ImpersonateNamedPipeClient(handle)
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True
        )
        try:
            pid = _named_pipe_client_pid(handle)
        except Exception:
            pid = None
        return _context_from_token(token, process_id=pid)
    finally:
        _close_handle_safely(token)
        try:
            win32security.RevertToSelf()
        except Exception:
            pass


def _named_pipe_client_pid(handle) -> int:
    """Return the kernel-reported PID for the connected named-pipe client.

    GetNamedPipeClientProcessId is available on supported BC Sentinel Windows
    targets (Vista+/Server 2008+).  We call Kernel32 directly rather than
    depending on a pywin32 wrapper that is not present in every build.
    """
    if os.name != "nt":
        raise NamedPipeUnavailable("Named-pipe client PID lookup is Windows-only.")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = kernel32.GetNamedPipeClientProcessId
    fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    fn.restype = wintypes.BOOL
    pid = wintypes.ULONG(0)
    raw_handle = int(handle)
    if not fn(wintypes.HANDLE(raw_handle), ctypes.byref(pid)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not pid.value:
        raise NamedPipeUnavailable("Windows returned an invalid named-pipe client PID.")
    return int(pid.value)


def _client_context_via_process_token(handle) -> ClientContext:
    """Resolve client identity from the kernel-reported client process.

    This is a fail-closed fallback for systems where named-pipe impersonation
    cannot yield a queryable thread token. The service runs as LocalSystem and
    opens only TOKEN_QUERY on the exact process currently connected to the pipe.
    """
    _, win32api, win32con, _, _, win32security = _imports()
    pid = _named_pipe_client_pid(handle)
    process = None
    token = None
    try:
        query_limited = getattr(win32con, "PROCESS_QUERY_LIMITED_INFORMATION", 0x1000)
        process = win32api.OpenProcess(query_limited, False, pid)
        token = win32security.OpenProcessToken(process, win32security.TOKEN_QUERY)
        return _context_from_token(token, process_id=pid)
    finally:
        _close_handle_safely(token)
        _close_handle_safely(process)


def _contexts_match_for_admin_upgrade(impersonated: ClientContext, process: ClientContext) -> bool:
    """Require the kernel PID process token to describe the same peer."""
    if not impersonated.sid or not process.sid or impersonated.sid != process.sid:
        return False
    if (
        impersonated.process_id is not None
        and process.process_id is not None
        and impersonated.process_id != process.process_id
    ):
        return False
    if (
        impersonated.session_id is not None
        and process.session_id is not None
        and impersonated.session_id != process.session_id
    ):
        return False
    return True


def client_context_from_pipe(handle) -> ClientContext:
    """Resolve a connected local client's Windows security context.

    Prefer true named-pipe impersonation for peer identity.  Some Windows
    impersonation-token paths can under-report administrator membership even
    for an actually elevated process.  When that happens, consult the primary
    token of the exact kernel-reported client PID and accept its admin bit only
    when SID/session/PID still describe the same peer.  Any mismatch stays
    non-admin (fail closed).
    """
    errors = []
    impersonated = None
    try:
        impersonated = _client_context_via_impersonation(handle)
    except Exception as exc:
        errors.append(f"impersonation={type(exc).__name__}:{exc}")

    if impersonated is not None:
        if impersonated.is_admin:
            return impersonated
        try:
            process = _client_context_via_process_token(handle)
            if process.is_admin and _contexts_match_for_admin_upgrade(impersonated, process):
                return ClientContext(
                    local=impersonated.local and process.local,
                    authenticated=impersonated.authenticated and process.authenticated,
                    is_admin=True,
                    sid=impersonated.sid,
                    session_id=impersonated.session_id if impersonated.session_id is not None else process.session_id,
                    transport=impersonated.transport,
                    process_id=impersonated.process_id if impersonated.process_id is not None else process.process_id,
                )
        except Exception as exc:
            errors.append(f"process_token={type(exc).__name__}:{exc}")
        return impersonated

    try:
        return _client_context_via_process_token(handle)
    except Exception as exc:
        errors.append(f"process_token={type(exc).__name__}:{exc}")
    raise NamedPipeUnavailable("; ".join(errors) or "named-pipe client identity unavailable")


def _read_message(handle) -> bytes:
    pywintypes, _, _, win32file, _, _ = _imports()
    chunks = []
    total = 0
    ERROR_MORE_DATA = 234
    while True:
        try:
            hr, data = win32file.ReadFile(handle, min(65536, MAX_MESSAGE_BYTES + 1 - total))
            chunks.append(bytes(data))
            total += len(data)
            if total > MAX_MESSAGE_BYTES:
                raise ValueError("message exceeds maximum size")
            if hr == 0:
                break
            if hr != ERROR_MORE_DATA:
                raise OSError(f"ReadFile returned error code {hr}")
        except pywintypes.error as exc:
            if int(getattr(exc, "winerror", exc.args[0] if exc.args else -1)) == ERROR_MORE_DATA:
                data = exc.args[2] if len(exc.args) > 2 and isinstance(exc.args[2], (bytes, bytearray)) else b""
                if data:
                    chunks.append(bytes(data))
                    total += len(data)
                    if total > MAX_MESSAGE_BYTES:
                        raise ValueError("message exceeds maximum size")
                continue
            raise
    return b"".join(chunks)


class WindowsNamedPipeServer:
    def __init__(self, core, *, pipe_name: str = PIPE_NAME):
        self.core = core
        self.pipe_name = pipe_name
        self._stop = threading.Event()
        self._threads: set[threading.Thread] = set()
        self._thread_lock = threading.RLock()
        self._prepared_handle = None
        self._ready = threading.Event()
        self._fatal_error = ""

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def fatal_error(self) -> str:
        return self._fatal_error

    def prepare(self) -> bool:
        """Create the first pipe instance synchronously.

        The Windows service calls this before it considers IPC ready.  This
        prevents a background transport-thread failure from leaving SCM with a
        superficially RUNNING service that has no control pipe.
        """
        if self._prepared_handle is not None:
            return True
        self._fatal_error = ""
        handle = self._create_pipe()
        self._prepared_handle = handle
        self._ready.set()
        return True

    def close_prepared(self) -> None:
        handle, self._prepared_handle = self._prepared_handle, None
        if handle is not None:
            try:
                import win32file
                win32file.CloseHandle(handle)
            except Exception:
                pass
        self._ready.clear()

    def _create_pipe(self):
        _, _, _, _, win32pipe, _ = _imports()
        return win32pipe.CreateNamedPipe(
            self.pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT
            | getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0x00000008),
            16,
            MAX_MESSAGE_BYTES,
            MAX_MESSAGE_BYTES,
            2000,
            build_pipe_security_attributes(),
        )

    def _handle_client(self, handle):
        _, _, _, win32file, win32pipe, _ = _imports()
        response = None
        try:
            # IMPORTANT: Windows documents ImpersonateNamedPipeClient as using
            # the security context of the *last message read from the pipe*.
            # Read the bounded request first, then impersonate, and only then
            # authorize/dispatch it.  Calling impersonation immediately after
            # ConnectNamedPipe can fail and used to make the handler disconnect
            # without ever writing a response (client-side ERROR_PIPE_NOT_CONNECTED / 233).
            try:
                raw = _read_message(handle)
            except ValueError as exc:
                response = response_error("unknown", "message_too_large", str(exc))
            except Exception as exc:
                response = response_error("unknown", "transport_read_error", str(exc))
            else:
                try:
                    context = client_context_from_pipe(handle)
                except Exception:
                    # Fail closed: never dispatch a request when transport
                    # identity could not be established. Do not expose the raw
                    # Win32 authentication error to an untrusted client.
                    response = response_error(
                        "unknown",
                        "transport_auth_error",
                        "named-pipe client identity verification failed",
                    )
                else:
                    try:
                        response = self.core.dispatch_bytes(raw, context)
                    except ValueError as exc:
                        response = response_error("unknown", "message_too_large", str(exc))
                    except Exception as exc:
                        response = response_error("unknown", "transport_error", str(exc))

            # Even rejected/invalid clients receive one bounded deterministic
            # response when the connection is still writable.  A per-client
            # write failure must not kill the long-running pipe accept loop.
            if response is not None:
                try:
                    win32file.WriteFile(handle, encode_message(response))
                    try:
                        win32file.FlushFileBuffers(handle)
                    except Exception:
                        pass
                except Exception:
                    pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except Exception:
                pass
            try:
                win32file.CloseHandle(handle)
            except Exception:
                pass

    def serve_forever(self):
        pywintypes, _, _, _, win32pipe, _ = _imports()
        ERROR_PIPE_CONNECTED = 535
        transient_streak = 0
        try:
            if self._prepared_handle is None:
                self.prepare()
            while not self._stop.is_set():
                if self._prepared_handle is not None:
                    handle, self._prepared_handle = self._prepared_handle, None
                else:
                    handle = self._create_pipe()
                try:
                    try:
                        win32pipe.ConnectNamedPipe(handle, None)
                        transient_streak = 0
                    except pywintypes.error as exc:
                        code = int(getattr(exc, "winerror", exc.args[0] if exc.args else -1))
                        if code == ERROR_PIPE_CONNECTED:
                            transient_streak = 0
                        elif is_transient_connect_error(code) and not self._stop.is_set():
                            # A client can disappear between CreateNamedPipe and
                            # ConnectNamedPipe. The current instance is stale, but
                            # the service itself is healthy. Recycle the instance.
                            transient_streak += 1
                            try:
                                import win32file
                                win32file.CloseHandle(handle)
                            except Exception:
                                pass
                            handle = None
                            if transient_streak >= 8:
                                raise NamedPipeUnavailable(
                                    f"named-pipe accept repeatedly failed with Win32 {code}"
                                ) from exc
                            self._stop.wait(min(0.05 * transient_streak, 0.4))
                            continue
                        else:
                            raise
                    if self._stop.is_set():
                        try:
                            import win32file
                            win32file.CloseHandle(handle)
                        except Exception:
                            pass
                        break
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(handle,),
                        name="BCS-ProtectionIPCClient",
                        daemon=True,
                    )
                    with self._thread_lock:
                        self._threads.add(thread)
                    thread.start()
                    with self._thread_lock:
                        self._threads = {t for t in self._threads if t.is_alive()}
                except Exception:
                    if handle is not None:
                        try:
                            import win32file
                            win32file.CloseHandle(handle)
                        except Exception:
                            pass
                    if not self._stop.is_set():
                        raise
        except Exception as exc:
            self._fatal_error = f"{type(exc).__name__}: {exc}"
            self._ready.clear()
            raise
        finally:
            if self._stop.is_set():
                self._ready.clear()

    def stop(self):
        self._stop.set()
        self.close_prepared()
        if os.name == "nt":
            # Connecting once releases a synchronous ConnectNamedPipe call.
            try:
                _, _, win32con, win32file, _, _ = _imports()
                handle = win32file.CreateFile(
                    self.pipe_name,
                    win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                    0,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None,
                )
                win32file.CloseHandle(handle)
            except Exception:
                pass
        with self._thread_lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=1.0)
