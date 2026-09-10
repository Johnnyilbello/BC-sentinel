from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import tools.v011_beta2_b2_request_op_compat as compat


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fixture_service() -> str:
    return f'''# {compat.SERVICE_MARKER}\nclass ProtectionServiceCore:\n    def dispatch_validated(self, request, context):\n        {compat.BUGGY}\n        return op\n# {compat.SERVICE_MARKER}\n'''


def _prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    root = tmp_path
    sentinel = root / "sentinel"
    sentinel.mkdir()
    service = _fixture_service()
    protocol = "protocol-b1b\n"
    client = "client-b1b\n"
    (sentinel / "protection_service_core.py").write_text(service, encoding="utf-8")
    (sentinel / "protection_protocol.py").write_text(protocol, encoding="utf-8")
    (sentinel / "protection_client.py").write_text(client, encoding="utf-8")
    monkeypatch.setattr(compat, "BASE_SERVICE_SHA256", _sha(service))
    monkeypatch.setattr(compat, "EXPECTED_PROTOCOL_SHA256", _sha(protocol))
    monkeypatch.setattr(compat, "EXPECTED_CLIENT_SHA256", _sha(client))
    return root, service


def test_request_op_compat_applies_exactly_one_transform_and_preserves_baseline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, original = _prepare(tmp_path, monkeypatch)
    result = compat.apply(root)
    current = (root / compat.SERVICE_REL).read_text(encoding="utf-8")
    backup = (root / compat.BACKUP_REL).read_text(encoding="utf-8")

    assert result["passed"] is True
    assert backup == original
    assert current == original.replace(compat.BUGGY, compat.FIXED, 1)
    assert current.count(compat.FIXED) == 1
    assert compat.BUGGY not in current


def test_request_op_compat_is_idempotent_only_for_verified_lineage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, _ = _prepare(tmp_path, monkeypatch)
    first = compat.apply(root)
    second = compat.apply(root)
    assert first["service_sha256"] == second["service_sha256"]
    assert second["passed"] is True


def test_request_op_compat_rejects_extra_service_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, _ = _prepare(tmp_path, monkeypatch)
    compat.apply(root)
    service = root / compat.SERVICE_REL
    service.write_text(service.read_text(encoding="utf-8") + "# unexpected drift\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="neither accepted B1b baseline nor valid B2 request.op lineage"):
        compat.apply(root)


def test_request_op_compat_rejects_wrong_protocol_or_client_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, _ = _prepare(tmp_path, monkeypatch)
    (root / compat.PROTOCOL_REL).write_text("tampered\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="protocol source is not the accepted B1b version"):
        compat.apply(root)


def test_transform_refuses_multiple_buggy_dispatch_expressions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    service = _fixture_service().replace("return op", compat.BUGGY + "\n        return op")
    monkeypatch.setattr(compat, "BASE_SERVICE_SHA256", _sha(service))
    with pytest.raises(RuntimeError, match="exactly one"):
        compat.transform(service)
