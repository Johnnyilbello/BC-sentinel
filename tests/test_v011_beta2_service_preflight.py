from __future__ import annotations

from pathlib import Path

from tools.v011_beta2_service_preflight import inspect_service


def test_preflight_fails_closed_when_full_service_core_is_missing(tmp_path: Path):
    result = inspect_service(tmp_path)
    assert result["passed"] is False
    assert result["reason"] == "FULL-only protection_service_core.py not found"


def test_preflight_extracts_runtime_and_service_anchors_without_mutation(tmp_path: Path):
    sentinel = tmp_path / "sentinel"
    packaging = tmp_path / "packaging"
    sentinel.mkdir()
    packaging.mkdir()
    target = sentinel / "protection_service_core.py"
    original = '''from sentinel.etw_monitor import ETWMonitor\n\nclass ProtectionRuntime:\n    def __init__(self):\n        self.etw = ETWMonitor(None, None, event_callback=self._on_security_event)\n\n    def _on_security_event(self, event):\n        return event\n\n    def dispatch(self, operation, payload):\n        if operation == "status":\n            return self.status()\n        return {"incident": None}\n\n    def status(self):\n        return {"transport": "windows_named_pipe"}\n'''
    target.write_text(original, encoding="utf-8")
    (packaging / "protection_service_entry.py").write_text(
        'PIPE_NAME = "BCSentinelProtection-v1"\n# named_pipe dispatch inbox incident\n',
        encoding="utf-8",
    )

    result = inspect_service(tmp_path)
    assert result["passed"] is True
    assert result["checks"]["protection_runtime_class"] is True
    assert result["checks"]["event_callback_reference"] is True
    assert result["checks"]["dispatch_reference"] is True
    assert result["runtime"]["name"] == "ProtectionRuntime"
    methods = {item["name"] for item in result["runtime"]["methods"]}
    assert {"__init__", "_on_security_event", "dispatch", "status"}.issubset(methods)
    assert any(item["call"] == "ETWMonitor" for item in result["interesting_calls"])
    assert any(item["path"] == "packaging\\protection_service_entry.py" or item["path"] == "packaging/protection_service_entry.py" for item in result["related_files"])
    assert target.read_text(encoding="utf-8") == original
