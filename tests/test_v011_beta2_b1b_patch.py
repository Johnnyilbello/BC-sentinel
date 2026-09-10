from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tools.v011_beta2_b1b_patch import (
    LEGACY_DISPATCH,
    LEGACY_PENDING,
    LEGACY_VALIDATE,
    PROTOCOL_MARKER,
    SERVICE_MARKER,
    _protocol_update,
    _service_update,
)


PROTOCOL_FIXTURE = '''
READ_OPERATIONS = frozenset({"status"})
PRIVILEGED_OPERATIONS = frozenset({"terminate_process"})
ALL_OPERATIONS = READ_OPERATIONS | PRIVILEGED_OPERATIONS

class ProtocolError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message

def _validate_payload(op, payload):
    if not isinstance(payload, dict):
        raise ProtocolError("invalid_payload", "payload must be an object")
    return dict(payload)
'''


SERVICE_FIXTURE = '''
from .edr_service_bridge import EdrServiceBridge

def response_ok(request_id, **payload):
    return {"ok": True, "request_id": request_id, **payload}

def response_error(request_id, code, message):
    return {"ok": False, "request_id": request_id, "code": code, "message": message}

class ProtectionRuntime:
    def __init__(self):
        self.edr_bridge = None
    def pending_threats(self, limit=100):
        return [{"source": "legacy"}]

class ProtectionServiceCore:
    def _authorize(self, request, context):
        return True
    def _enforce_request_rate(self, request, context):
        return True
    def dispatch_validated(self, request, context):
        return response_ok(request.request_id, legacy=True)
'''


def test_protocol_update_adds_edr_allowlists_and_strict_validation(tmp_path: Path):
    path = tmp_path / "protection_protocol.py"
    updated = _protocol_update(PROTOCOL_FIXTURE, path)
    ast.parse(updated)
    assert updated.count(PROTOCOL_MARKER) == 2
    assert f"def {LEGACY_VALIDATE}(" in updated
    ns = {}
    exec(updated, ns)
    assert "edr_timeline" in ns["READ_OPERATIONS"]
    assert "edr_update_retention" in ns["PRIVILEGED_OPERATIONS"]
    assert ns["_validate_payload"]("edr_timeline", {"limit": 50})["limit"] == 50
    with pytest.raises(ns["ProtocolError"]):
        ns["_validate_payload"]("edr_timeline", {"limit": 50, "shell": "x"})
    with pytest.raises(ns["ProtocolError"]):
        ns["_validate_payload"]("edr_timeline", {"limit": 501})


def test_protocol_update_preserves_legacy_operations(tmp_path: Path):
    updated = _protocol_update(PROTOCOL_FIXTURE, tmp_path / "protection_protocol.py")
    ns = {}
    exec(updated, ns)
    assert ns["_validate_payload"]("status", {"x": 1}) == {"x": 1}


def test_service_update_wraps_only_edr_and_preserves_legacy_dispatch(tmp_path: Path):
    path = tmp_path / "protection_service_core.py"
    updated = _service_update(SERVICE_FIXTURE, path)
    ast.parse(updated)
    assert updated.count(SERVICE_MARKER) == 2
    assert f"def {LEGACY_DISPATCH}(" in updated
    assert f"def {LEGACY_PENDING}(" in updated
    assert "self._authorize(request, context)" in updated
    assert "self._enforce_request_rate(request, context)" in updated
    assert "self.runtime.edr_bridge.dispatch_read(op, payload)" in updated
    assert "self.runtime.edr_bridge.dispatch_privileged(op, payload)" in updated
    assert "self.edr_bridge.security_inbox_items(limit=bounded)" in updated


def test_service_update_does_not_add_destructive_or_shell_behavior(tmp_path: Path):
    updated = _service_update(SERVICE_FIXTURE, tmp_path / "protection_service_core.py")
    forbidden = (
        "automatic_process_kill", "automatic_file_delete", "automatic_host_isolation",
        "subprocess", "os.system", "shell=True", "pickle.loads",
    )
    assert all(term not in updated for term in forbidden)
