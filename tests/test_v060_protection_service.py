from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.service_update import version_key
from sentinel.config import Settings
from sentinel.protection_protocol import (
    ClientContext,
    MAX_MESSAGE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    build_request,
    decode_request,
    encode_message,
    validate_request,
)
from sentinel.protection_service_core import (
    ComponentState,
    ProtectionConfigStore,
    ProtectionServiceCore,
    ServiceHealth,
)


SECRET = "a" * 64


def test_protocol_roundtrip_is_strict_json():
    request = build_request("events", SECRET, since=0, limit=20)
    validated = decode_request(encode_message(request))
    assert validated.version == PROTOCOL_VERSION
    assert validated.op == "events"
    assert validated.payload == {"since": 0, "limit": 20}


def test_protocol_rejects_malformed_json():
    with pytest.raises(ProtocolError) as exc:
        decode_request(b"{not-json")
    assert exc.value.code == "malformed_json"


def test_protocol_rejects_unknown_operation():
    request = {
        "version": PROTOCOL_VERSION,
        "request_id": "abc123",
        "op": "exec",
        "token": SECRET,
        "payload": {},
    }
    with pytest.raises(ProtocolError) as exc:
        validate_request(request)
    assert exc.value.code == "unsupported_operation"


def test_protocol_rejects_wrong_version():
    request = build_request("status", SECRET)
    request["version"] = 999
    with pytest.raises(ProtocolError) as exc:
        validate_request(request)
    assert exc.value.code == "unsupported_version"


def test_protocol_rejects_unknown_payload_fields():
    request = build_request("status", SECRET)
    request["payload"] = {"shell": "whoami"}
    with pytest.raises(ProtocolError) as exc:
        validate_request(request)
    assert exc.value.code == "invalid_payload"


def test_protocol_rejects_oversized_message():
    raw = b"{" + (b"x" * MAX_MESSAGE_BYTES) + b"}"
    with pytest.raises(ProtocolError) as exc:
        decode_request(raw)
    assert exc.value.code == "message_too_large"


def test_protocol_never_accepts_pickle_payload():
    # Pickle protocol bytes are not JSON and must fail before any deserialization.
    raw = b"\x80\x04cposix\nsystem\n."
    with pytest.raises(ProtocolError):
        decode_request(raw)


class FakeEvents:
    sequence = 0
    def since(self, seq, limit):
        return []


class FakeRuntime:
    def __init__(self):
        self.secret = SECRET
        self.events = FakeEvents()
        self.network = False
        self.protection_enabled = True
        self.config = {}

    def status(self):
        return {
            "service": "BCSentinelProtection",
            "health": "HEALTHY",
            "network": self.network,
            "protection_enabled": self.protection_enabled,
        }

    def set_network_collection(self, enabled):
        self.network = bool(enabled)
        return True

    def set_protection_enabled(self, enabled):
        self.protection_enabled = bool(enabled)
        return True

    def update_config(self, changes):
        self.config.update(changes)
        return dict(self.config)

    def attribute(self, path):
        return {"path": path}

    def process_chain(self, pid):
        return [{"pid": pid}]

    def incidents(self, limit, min_score):
        return []

    def incident(self, incident_id):
        return None

    def quarantine_items(self):
        return []


def _request(op, **payload):
    return build_request(op, SECRET, **payload)


def test_read_only_operation_does_not_require_admin():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    result = core.dispatch(
        _request("status"),
        ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-test"),
    )
    assert result["ok"] is True
    assert result["status"]["health"] == "HEALTHY"


def test_privileged_operation_requires_authenticated_transport():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    result = core.dispatch(
        _request("set_network_collection", enabled=True),
        ClientContext(local=True, authenticated=False, is_admin=True),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "unauthorized"


def test_privileged_operation_requires_admin_identity():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    result = core.dispatch(
        _request("set_network_collection", enabled=True),
        ClientContext(local=True, authenticated=True, is_admin=False, sid="S-1-5-21-test"),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "admin_required"


def test_privileged_operation_succeeds_for_authenticated_admin():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    result = core.dispatch(
        _request("set_network_collection", enabled=True),
        ClientContext(local=True, authenticated=True, is_admin=True, sid="S-1-5-32-544"),
    )
    assert result["ok"] is True
    assert result["network"] is True


def test_bad_installation_token_fails_closed():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    request = build_request("status", "b" * 64)
    result = core.dispatch(
        request,
        ClientContext(local=True, authenticated=True, is_admin=True),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "unauthorized"


def test_remote_context_is_rejected_even_with_valid_token():
    core = ProtectionServiceCore(FakeRuntime(), secret=SECRET)
    result = core.dispatch(
        _request("status"),
        ClientContext(local=False, authenticated=True, is_admin=True),
    )
    assert result["ok"] is False
    assert result["error"]["code"] == "unauthorized"


def test_config_store_detects_tampering(tmp_path):
    store = ProtectionConfigStore(SECRET)
    store.path = tmp_path / "protection-config.json"
    store.sig_path = tmp_path / "protection-config.sig"
    settings = Settings.defaults()
    settings.realtime_enabled = True
    store.save(settings)
    assert store.load().realtime_enabled is True

    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["realtime_enabled"] = False
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        store.load()


def test_config_store_atomic_update_roundtrip(tmp_path):
    store = ProtectionConfigStore(SECRET)
    store.path = tmp_path / "protection-config.json"
    store.sig_path = tmp_path / "protection-config.sig"
    store.save(Settings.defaults())
    updated = store.update({"network_enabled": False, "scan_size_limit_mb": 128})
    assert updated.network_enabled is False
    assert updated.scan_size_limit_mb == 128
    assert not (tmp_path / "protection-config.json.tmp").exists()
    assert not (tmp_path / "protection-config.sig.tmp").exists()


def test_health_model_degrades_if_critical_component_is_down():
    class Bare:
        _health = ServiceHealth.HEALTHY
        _components = {
            "realtime": ComponentState(True, False, True),
            "correlation": ComponentState(True, True, True),
        }
    # Use the real pure function without constructing Windows/runtime backends.
    from sentinel.protection_service_core import ProtectionRuntime
    assert ProtectionRuntime._derive_health(Bare()) == ServiceHealth.DEGRADED


def test_health_model_is_healthy_when_all_enabled_components_run():
    class Bare:
        _health = ServiceHealth.HEALTHY
        _components = {
            "realtime": ComponentState(True, True, True),
            "network": ComponentState(True, True, False),
            "etw": ComponentState(False, False, False),
        }
    from sentinel.protection_service_core import ProtectionRuntime
    assert ProtectionRuntime._derive_health(Bare()) == ServiceHealth.HEALTHY


def test_production_ipc_has_no_tcp_listener_or_pickle():
    core = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8").lower()
    transport = Path("sentinel/protection_transport_windows.py").read_text(encoding="utf-8").lower()
    legacy = Path("sentinel/telemetry_service_core.py").read_text(encoding="utf-8").lower()
    combined = core + transport
    assert "socketserver" not in combined
    assert "create_connection" not in combined
    assert "pickle.loads" not in combined
    assert "localhost" not in combined
    assert "legacy tcp telemetry serving was removed" in legacy


def test_named_pipe_transport_impersonates_client_and_sets_acl():
    source = Path("sentinel/protection_transport_windows.py").read_text(encoding="utf-8")
    assert "ImpersonateNamedPipeClient" in source
    assert "CheckTokenMembership" in source
    assert "ConvertStringSecurityDescriptorToSecurityDescriptor" in source
    assert "CreateNamedPipe" in source


def test_service_source_has_no_arbitrary_command_api():
    source = Path("sentinel/protection_service_core.py").read_text(encoding="utf-8").lower()
    for forbidden in ("subprocess.popen", "os.system", "shell=true", 'op == "exec"', 'op == "shell"'):
        assert forbidden not in source


def test_ui_does_not_start_duplicate_engines_when_service_owns_protection():
    source = Path("app/ui/main_window.py").read_text(encoding="utf-8")
    assert "service_owns_protection" in source
    assert "The service is canonical" in source
    assert "self.realtime.stop()" in source
    assert "self.procmon.stop()" in source


def test_named_pipe_prepare_is_synchronous_and_marks_ready(monkeypatch):
    from sentinel.protection_transport_windows import WindowsNamedPipeServer
    marker = object()
    server = WindowsNamedPipeServer(object())
    monkeypatch.setattr(server, "_create_pipe", lambda: marker)
    assert server.prepare() is True
    assert server.ready is True
    assert server._prepared_handle is marker
    server.close_prepared()
    assert server.ready is False


def test_service_waits_for_pipe_bootstrap_before_running_status():
    source = Path("sentinel/protection_service_windows.py").read_text(encoding="utf-8")
    prepare_at = source.index("self.server.prepare()")
    running_at = source.index("SERVICE_RUNNING", prepare_at)
    thread_at = source.index("target=self._run_pipe_server", prepare_at)
    assert prepare_at < thread_at < running_at
    assert "IPC bootstrap failed" in source
    assert "win32event.SetEvent(self.stop_event)" in source


def test_official_build_delegates_hardened_service_build():
    source = Path("bootstrap.ps1").read_text(encoding="utf-8-sig")
    assert "BUILD-SERVIZIO-PROTEZIONE.ps1" in source
    dedicated = Path("BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert '"--paths", $projectRoot' in dedicated
    assert '"--collect-submodules", "sentinel"' in dedicated
    for module in ("win32pipe", "win32file", "win32security", "win32api", "win32con", "pywintypes"):
        assert f'"--hidden-import", "{module}"' in dedicated


def test_installer_requires_named_pipe_selftest_before_service_install():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8")
    assert "& $deployed pipe-selftest" in source
    assert source.index("& $deployed pipe-selftest") < source.index("& $deployed --startup auto install")


def test_beta1_installer_requires_frozen_service_host():
    source = Path("INSTALLA-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8")
    assert "Protection Service compilato non trovato" in source
    assert "BUILD-SERVIZIO-PROTEZIONE.ps1" in source


def test_dedicated_service_build_script_uses_project_root_and_selftest():
    source = Path("BUILD-SERVIZIO-PROTEZIONE.ps1").read_text(encoding="utf-8-sig")
    assert '"--paths", $projectRoot' in source
    assert '"--collect-submodules", "sentinel"' in source
    assert "pipe-selftest" in source


def test_beta2_reads_request_before_named_pipe_impersonation():
    source = Path("sentinel/protection_transport_windows.py").read_text(encoding="utf-8")
    handler = source[source.index("    def _handle_client"):source.index("    def serve_forever", source.index("    def _handle_client"))]
    assert handler.index("raw = _read_message(handle)") < handler.index("context = client_context_from_pipe(handle)")


def test_beta2_transport_identity_failure_is_fail_closed_before_dispatch():
    source = Path("sentinel/protection_transport_windows.py").read_text(encoding="utf-8")
    handler = source[source.index("    def _handle_client"):source.index("    def serve_forever", source.index("    def _handle_client"))]
    assert '"transport_auth_error"' in handler
    assert "self.core.dispatch_bytes(raw, context)" in handler
    assert "Fail closed" in handler


def test_beta2_service_version_is_consistent():
    # Historical beta.2 transport fixes remain while the release advances.
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.6.0")


def test_beta2_handler_reads_then_authenticates_then_dispatches(monkeypatch):
    import sentinel.protection_transport_windows as transport

    order = []
    writes = []

    class FakeWin32File:
        @staticmethod
        def WriteFile(handle, data):
            order.append("write")
            writes.append(bytes(data))
            return 0, len(data)

        @staticmethod
        def FlushFileBuffers(handle):
            order.append("flush")

        @staticmethod
        def CloseHandle(handle):
            order.append("close")

    class FakeWin32Pipe:
        @staticmethod
        def DisconnectNamedPipe(handle):
            order.append("disconnect")

    class FakeCore:
        def dispatch_bytes(self, raw, context):
            order.append("dispatch")
            assert raw == b'{"probe":true}'
            assert context.authenticated is True
            return {"version": 1, "request_id": "probe", "ok": True}

    context = ClientContext(
        local=True,
        authenticated=True,
        is_admin=True,
        sid="S-1-5-32-544",
        transport="test_pipe",
    )

    monkeypatch.setattr(
        transport,
        "_imports",
        lambda: (Exception, object(), object(), FakeWin32File, FakeWin32Pipe, object()),
    )
    monkeypatch.setattr(
        transport,
        "_read_message",
        lambda handle: order.append("read") or b'{"probe":true}',
    )
    monkeypatch.setattr(
        transport,
        "client_context_from_pipe",
        lambda handle: order.append("impersonate") or context,
    )

    server = transport.WindowsNamedPipeServer(FakeCore())
    server._handle_client(object())

    assert order.index("read") < order.index("impersonate") < order.index("dispatch") < order.index("write")
    assert writes


def test_beta3_client_identity_falls_back_to_kernel_client_pid(monkeypatch):
    import sentinel.protection_transport_windows as transport

    expected = ClientContext(
        local=True,
        authenticated=True,
        is_admin=True,
        sid="S-1-5-21-beta3",
        session_id=7,
        transport="windows_named_pipe",
    )
    order = []

    def fail_impersonation(handle):
        order.append("impersonation")
        raise RuntimeError("no queryable impersonation token")

    def pid_token(handle):
        order.append("process_token")
        return expected

    monkeypatch.setattr(transport, "_client_context_via_impersonation", fail_impersonation)
    monkeypatch.setattr(transport, "_client_context_via_process_token", pid_token)

    context = transport.client_context_from_pipe(object())
    assert context == expected
    assert order == ["impersonation", "process_token"]




def test_v062_elevated_process_token_can_correct_impersonation_admin_false(monkeypatch):
    import sentinel.protection_transport_windows as transport

    impersonated = ClientContext(
        local=True, authenticated=True, is_admin=False, sid="S-1-5-21-user",
        session_id=11, transport="windows_named_pipe", process_id=4242,
    )
    process = ClientContext(
        local=True, authenticated=True, is_admin=True, sid="S-1-5-21-user",
        session_id=11, transport="windows_named_pipe", process_id=4242,
    )
    monkeypatch.setattr(transport, "_client_context_via_impersonation", lambda handle: impersonated)
    monkeypatch.setattr(transport, "_client_context_via_process_token", lambda handle: process)

    context = transport.client_context_from_pipe(object())
    assert context.is_admin is True
    assert context.sid == impersonated.sid
    assert context.session_id == 11
    assert context.process_id == 4242


def test_v062_process_token_admin_cannot_cross_identity_boundary(monkeypatch):
    import sentinel.protection_transport_windows as transport

    impersonated = ClientContext(
        local=True, authenticated=True, is_admin=False, sid="S-1-5-21-original",
        session_id=11, transport="windows_named_pipe", process_id=4242,
    )
    mismatched = ClientContext(
        local=True, authenticated=True, is_admin=True, sid="S-1-5-21-other",
        session_id=11, transport="windows_named_pipe", process_id=4242,
    )
    monkeypatch.setattr(transport, "_client_context_via_impersonation", lambda handle: impersonated)
    monkeypatch.setattr(transport, "_client_context_via_process_token", lambda handle: mismatched)

    context = transport.client_context_from_pipe(object())
    assert context.is_admin is False
    assert context.sid == impersonated.sid

def test_beta3_identity_failure_remains_fail_closed(monkeypatch):
    import sentinel.protection_transport_windows as transport

    monkeypatch.setattr(
        transport,
        "_client_context_via_impersonation",
        lambda handle: (_ for _ in ()).throw(RuntimeError("impersonation failed")),
    )
    monkeypatch.setattr(
        transport,
        "_client_context_via_process_token",
        lambda handle: (_ for _ in ()).throw(RuntimeError("pid token failed")),
    )
    with pytest.raises(transport.NamedPipeUnavailable) as exc:
        transport.client_context_from_pipe(object())
    assert "impersonation=" in str(exc.value)
    assert "process_token=" in str(exc.value)


def test_beta3_pipe_rejects_remote_clients_flag_in_source():
    source = Path("sentinel/protection_transport_windows.py").read_text(encoding="utf-8")
    assert "PIPE_REJECT_REMOTE_CLIENTS" in source
    assert "GetNamedPipeClientProcessId" in source
    assert "OpenProcessToken" in source


def test_beta3_service_version_line_advanced_without_regressing_beta3_fixes():
    from sentinel.config import APP_VERSION
    assert version_key(APP_VERSION) >= version_key("0.6.2-beta.1")
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{APP_VERSION.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")}"' in pyproject
