from __future__ import annotations

from pathlib import Path

import pytest

from tools.v011_beta2_service_runtime_patch import (
    MARKER,
    apply_runtime_patch,
    verify_runtime_patch,
)


FIXTURE = '''from __future__ import annotations
import time

class ProtectionRuntime:
    def __init__(self):
        self.settings = None
        self.value = 1

    def _on_event(self, event):
        self.value += 1

    def status(self):
        return {"health": "healthy", "value": self.value}

    def other(self):
        return True
'''


def test_runtime_patcher_adds_service_owned_edr_ingestion_and_status(tmp_path: Path):
    target = tmp_path / "protection_service_core.py"
    target.write_text(FIXTURE, encoding="utf-8")

    result = apply_runtime_patch(target, expected_sha256=None)
    text = target.read_text(encoding="utf-8")

    assert result["passed"] is True
    assert result["patched"] is True
    assert text.count(MARKER) == 3
    assert text.count("from .edr_service_bridge import EdrServiceBridge") == 1
    assert "self.edr_bridge = EdrServiceBridge(" in text
    assert "_edr_bridge.ingest_security_event(event)" in text
    assert "def _v011_beta2_legacy_status(self):" in text
    assert "def status(self):" in text
    assert 'payload["edr"] = self.edr_bridge.status()' in text
    assert (tmp_path / "protection_service_core.py.pre-v011-beta2-b1a.bak").is_file()


def test_runtime_patcher_is_idempotent(tmp_path: Path):
    target = tmp_path / "protection_service_core.py"
    target.write_text(FIXTURE, encoding="utf-8")

    first = apply_runtime_patch(target, expected_sha256=None)
    first_text = target.read_text(encoding="utf-8")
    second = apply_runtime_patch(target, expected_sha256=None)

    assert first["patched"] is True
    assert second["patched"] is False
    assert second["already_compatible"] is True
    assert target.read_text(encoding="utf-8") == first_text
    assert verify_runtime_patch(target)["passed"] is True


def test_runtime_patcher_refuses_source_hash_drift(tmp_path: Path):
    target = tmp_path / "protection_service_core.py"
    target.write_text(FIXTURE, encoding="utf-8")

    with pytest.raises(RuntimeError, match="source changed since B0 preflight"):
        apply_runtime_patch(target, expected_sha256="0" * 64)

    assert target.read_text(encoding="utf-8") == FIXTURE


def test_runtime_patcher_refuses_unexpected_runtime_shape(tmp_path: Path):
    target = tmp_path / "protection_service_core.py"
    target.write_text(
        "class ProtectionRuntime:\n    def __init__(self):\n        pass\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="_on_event"):
        apply_runtime_patch(target, expected_sha256=None)
