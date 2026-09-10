from __future__ import annotations

from pathlib import Path

from tools.v011_beta2_ipc_preflight import inspect_ipc


def _write_fixture(root: Path) -> None:
    sentinel = root / "sentinel"
    sentinel.mkdir()
    (sentinel / "protection_protocol.py").write_text(
        '''PRIVILEGED_OPERATIONS = {"set_config"}\nMAX_MESSAGE_SIZE = 262144\ndef validate_request(raw):\n    return raw\n''',
        encoding="utf-8",
    )
    (sentinel / "protection_service_core.py").write_text(
        '''# bc-sentinel-v011-beta2-service-runtime-v1\nclass ProtectionServiceCore:\n    def _authorize(self, request, context):\n        return True\n    def dispatch_validated(self, request, context):\n        if request.operation == "status":\n            return self.runtime.status()\n        return None\n''',
        encoding="utf-8",
    )


def test_ipc_preflight_fails_closed_when_full_protocol_is_missing(tmp_path: Path):
    result = inspect_ipc(tmp_path)
    assert result["passed"] is False
    assert result["missing"]


def test_ipc_preflight_discovers_protocol_and_dispatch_without_mutation(tmp_path: Path, monkeypatch):
    _write_fixture(tmp_path)
    protocol = tmp_path / "sentinel" / "protection_protocol.py"
    service = tmp_path / "sentinel" / "protection_service_core.py"
    before_protocol = protocol.read_text(encoding="utf-8")
    before_service = service.read_text(encoding="utf-8")

    import tools.v011_beta2_ipc_preflight as module
    monkeypatch.setattr(module, "EXPECTED_B1A_SERVICE_SHA256", module._sha(before_service))
    result = module.inspect_ipc(tmp_path)

    assert result["passed"] is True
    assert result["checks"]["validate_request_present"] is True
    assert result["checks"]["privileged_operations_present"] is True
    assert result["checks"]["dispatch_validated_present"] is True
    assert result["checks"]["authorize_present"] is True
    names = {item["name"] for item in result["protocol"]["assignments"]}
    assert "PRIVILEGED_OPERATIONS" in names
    assert protocol.read_text(encoding="utf-8") == before_protocol
    assert service.read_text(encoding="utf-8") == before_service
